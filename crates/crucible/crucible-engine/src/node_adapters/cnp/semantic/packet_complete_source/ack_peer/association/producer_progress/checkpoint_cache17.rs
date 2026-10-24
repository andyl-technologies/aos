//! Lends the frozen post-retirement Producer checkpoint without redecoding it.

use super::*;
use crate::node_contract::WorldActivation;

impl PacketCompleteSemanticSource {
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source::ack_peer::association) fn with_original_producer_completed_cache17_data<
        R,
    >(
        &self,
        controller: &CnpController,
        world: &WorldActivation,
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
        if attempt.signature.is_none()
            || !attempt
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
        let (assigned, _, _) = sdk
            .authenticate_completed_checkpoint17_cache_data(controller, emitter, frontier, current)
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
        if record.native_receipt.original != *assigned
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
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source::ack_peer::association) fn original_producer_completed_cache17_counter_scratch_data()
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
            + size_of::<Ref<'static, ProducerProgressHistory>>()
            + size_of::<Result<Ref<'static, ProducerProgressHistory>, BorrowError>>()
    }
}
