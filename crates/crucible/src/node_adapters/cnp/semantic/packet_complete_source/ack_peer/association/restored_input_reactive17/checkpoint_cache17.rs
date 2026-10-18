//! Lends only a genuine Runtime-completed Input17 checkpoint in its live Source.
//!
//! The private Complete transition requires the original Source completion token
//! and actual Runtime acknowledgement disposition. A decoded historical action
//! or valid Source-MAC artifact never constructs this live owner.

use super::*;
use crucible_node_provider::reference_packet::service::restored_input_reactive17::PacketRestoredInputReactive17Command;

impl PacketCompleteSemanticSource {
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source::ack_peer::association) fn with_original_input_completed_cache17_data<
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
        let history = original
            .restored_inputs
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let attempt = history
            .completed_data()?
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let row = attempt.row.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        row.authenticate_owner_data(self, controller)?;
        if attempt.signature.is_none() || attempt.acknowledgement.is_none() {
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
        let post = attempt
            .post
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let artifact = attempt
            .artifact
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if record.native_receipt.original != *assigned
            || record.native_receipt.native_record != post.current_model
            || !matches!(
                artifact.request.command,
                PacketRestoredInputReactive17Command::Input { .. }
            )
        {
            return Err(RuntimeError::InvalidReceipt);
        }
        let result = inspect(record, underlying, &post.current_record, frontier);
        sdk.authenticate_completed_checkpoint17_cache_data(controller, emitter, frontier, current)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        result
    }
}

impl PacketCompleteSemanticSource {
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source::ack_peer::association) fn original_input_completed_cache17_counter_scratch_data()
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
            + size_of::<Ref<'static, InputReactive17History>>()
            + size_of::<Result<Ref<'static, InputReactive17History>, BorrowError>>()
    }
}
