//! Rechecks the genuine live completed bridge without serializing its MAC.
//!
//! The caller must borrow this bridge through both private completed Capture
//! owners. Their real once-completion path already verified the signature,
//! native outputs and Source claim. There is no portable constructor here.

use super::*;
use std::mem::size_of;

impl CaptureAdminBridge {
    pub(in super::super) fn authenticate_completed_cache17_data(
        &self,
        source: &PacketCompleteSemanticSource,
        controller: &CnpController,
        emitter: &OriginalCanonicalBlobAckEmitter,
        world: &WorldActivation,
    ) -> Result<(), RuntimeError> {
        if self.process != std::process::id()
            || self.thread != std::thread::current().id()
            || !std::ptr::eq(self.source, source)
            || !std::ptr::eq(self.controller, controller)
            || !self.world.same_authority(world)
        {
            return Err(RuntimeError::ForeignAuthority);
        }

        // Only the defining live once path can retain this signed bridge and
        // subsequently publish both Complete phases. Presence is an invariant
        // of that path, not a validator for a signature supplied as DATA.
        if self.signature.is_none() || self.prefix_frontier.get() >= self.frontier.get() {
            return Err(RuntimeError::InvalidReceipt);
        }
        let completed = controller
            .original_completed_restored_settled_capture_precredit_data(emitter)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        if completed.frontier_data() != self.frontier
            || completed
                .prefix_frontier_data()
                .map_err(|_| RuntimeError::InvalidReceipt)?
                != self.prefix_frontier
            || completed.request_data().history_next_sequence != self.prefix_frontier
            || completed.request_data().current_record != self.measurement
            || completed.request_data().current_model != self.model
            || completed.request_data().capture.capture_id != self.capture_id
            || completed.request_data().capture_operation != self.capture_operation
            || completed.receipt_data().native_after_ref != self.native_after
            || completed
                .confirmation_request_data()
                .settled_capture_request
                != self.capture_request
        {
            return Err(RuntimeError::InvalidReceipt);
        }
        Ok(())
    }

    pub(in super::super) fn completed_cache17_counter_scratch_data() -> usize {
        CnpController::original_completed_restored_settled_capture_precredit_counter_scratch_data()
            + size_of::<&Self>()
            + size_of::<&PacketCompleteSemanticSource>()
            + size_of::<&CnpController>()
            + size_of::<&OriginalCanonicalBlobAckEmitter>()
            + size_of::<&WorldActivation>()
            + size_of::<OriginalCompletedRestoredSettledCaptureData<'static>>()
            + size_of::<
                Result<
                    OriginalCompletedRestoredSettledCaptureData<'static>,
                    crucible_node_transport::ProviderError,
                >,
            >()
            + size_of::<Result<U64, crucible_node_transport::ProviderError>>()
            + size_of::<Result<(), RuntimeError>>()
            + size_of::<std::thread::Thread>()
            + size_of::<ThreadId>()
            + size_of::<u32>()
            + size_of::<U64>() * 2
            + size_of::<bool>()
    }
}
