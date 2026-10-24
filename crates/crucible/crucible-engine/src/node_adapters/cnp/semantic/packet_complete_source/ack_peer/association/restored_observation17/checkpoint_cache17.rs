//! Lends only append-only Observe17 owners after actual Runtime completion.

use super::*;

impl PacketCompleteSemanticSource {
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source::ack_peer::association) fn original_signed_observation17_completed_cache_frontier_data(
        &self,
    ) -> Result<Option<U64>, RuntimeError> {
        let association = self
            .ack_peer_association
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let original = association.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        let owner = &original.restored_observations17;
        owner.require_idle_data()?;
        let completed = owner
            .completed
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let Some(attempt) = completed.last() else {
            return Ok(None);
        };
        Ok(Some(
            attempt
                .sdk
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?
                .completed_frontier_data()
                .ok_or(RuntimeError::InvalidReceipt)?,
        ))
    }

    pub(in crate::node_adapters::cnp::semantic::packet_complete_source::ack_peer::association) fn with_original_signed_observation17_completed_cache_data<
        R,
    >(
        &self,
        controller: &CnpController,
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
        let owner = &original.restored_observations17;
        owner.require_idle_data()?;
        let completed = owner
            .completed
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let attempt = completed.last().ok_or(RuntimeError::OwnerUnavailable)?;
        if attempt.stage != Stage::Complete || attempt.signature.is_none() {
            return Err(RuntimeError::OutstandingObligations);
        }
        let sdk = attempt.sdk.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        let (assigned, _, _) = sdk
            .authenticate_completed_checkpoint17_cache_data(controller, emitter, frontier, current)
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
        let request = attempt
            .request
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if record.native_receipt.original != *assigned
            || request.command != PacketRestoredInputReactive17Command::Observe
            || attempt
                .scheduling
                .as_ref()
                .is_none_or(|value| value.proof_ref != *measurement)
        {
            return Err(RuntimeError::InvalidReceipt);
        }
        let result = inspect(record, underlying, measurement, frontier);
        sdk.authenticate_completed_checkpoint17_cache_data(controller, emitter, frontier, current)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        result
    }
}

impl PacketCompleteSemanticSource {
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source::ack_peer::association) fn original_signed_observation17_completed_cache_counter_scratch_data()
    -> usize {
        use std::{
            cell::{BorrowError, Ref},
            mem::size_of,
        };
        size_of::<Ref<'static, Option<OriginalAckPeerAssociation>>>()
            + size_of::<Result<Ref<'static, Option<OriginalAckPeerAssociation>>, BorrowError>>()
            + size_of::<&PacketNativeRestoredRecord>()
            + size_of::<&PacketNative5UnderlyingRecord>()
            + size_of::<&ContentRef>()
            + size_of::<U64>()
            + size_of::<Result<(), RuntimeError>>()
            + size_of::<Ref<'static, Vec<Observation17Attempt>>>()
            + size_of::<Result<Ref<'static, Vec<Observation17Attempt>>, BorrowError>>()
            + size_of::<Ref<'static, Option<Observation17Attempt>>>()
    }
}
