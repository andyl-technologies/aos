//! Lends immutable first ancestry without rebuilding completed proof DTOs.

use super::*;
use crucible_node_format::U64;
use crucible_node_transport::reference_packet::service::complete_restore::activation::PacketRestorationActivationScope;

impl PacketCompleteSemanticSource {
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source::ack_peer::association) fn with_original_first_completed_cache17_data<
        R,
    >(
        &self,
        controller: &CnpController,
        frontier: U64,
        current: bool,
        inspect: impl FnOnce(
            &PacketRestorationActivationScope,
            &PacketNativeRestoredRecord,
            &PacketNative5UnderlyingRecord,
            &ContentRef,
            U64,
            [u8; 32],
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
        let (record, underlying, scheduling, binding) =
            attempt.original_completed_cache17_data(self, controller)?;
        let pair = controller
            .original_completed_restoration_checkpoint17_cache_data(emitter, frontier, current)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        if record.native_receipt.original != *pair.original() {
            return Err(RuntimeError::InvalidReceipt);
        }
        let result = inspect(
            &pair.request_data().scope,
            record,
            underlying,
            &scheduling.proof_ref,
            pair.completed_frontier_data(),
            binding,
        );
        controller
            .original_completed_restoration_checkpoint17_cache_data(emitter, frontier, current)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        result
    }
}

impl PacketCompleteSemanticSource {
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source::ack_peer::association) fn original_first_completed_cache17_counter_scratch_data()
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
            + size_of::<(
                &PacketNativeRestoredRecord,
                &PacketNative5UnderlyingRecord,
                &NativeSchedulingObservation,
                [u8; 32],
            )>()
    }
}
