//! Checks host transaction completion without draining modeled pending work.
//!
//! The selected Capture attempt remains in the Boot reserve. Separate legacy
//! Capture and unfinished Fresh/restore transactions cannot enter this cut. No
//! predicate here requires empty events, reactions, publications or model queues.

use super::*;
use crate::client::DeadlineStream;
use crate::reference_packet::service::ack_emitter::OriginalRestorationReleased;

impl PacketEndpoint<DeadlineStream> {
    /// Borrows the genuine released restoration witness for a completed host cut.
    ///
    /// `None` means no retained restoration flight exists. The enclosing private
    /// initial-invocation selector must decide whether that separate cohort is
    /// eligible; absence is never restoration completion or a method grant.
    ///
    /// # Errors
    /// Refuses disconnected transport, separate legacy Capture, incomplete Fresh
    /// publication, or an active/partial restoration capsule in the same Some slot.
    pub(in crate::reference_packet) fn authenticate_settled_capture_host_cut17_data(
        &self,
    ) -> Result<Option<OriginalRestorationReleased>, ProviderError> {
        self.ensure_complete_origin()?;
        if self.capture.is_some()
            || self.capture_allocation_attempt.is_some()
            || self.pending_capture.is_some()
            || self.after_confirmation.is_some()
        {
            return Err(refused());
        }
        let Some(Transport::Connected(connection)) = self.transport.as_ref() else {
            return Err(refused());
        };
        let boot = self.canonical_ack_boot.as_ref().ok_or_else(refused)?;
        let released = match self.restore_commit.as_ref() {
            Some(flight) => Some(flight.authenticate_completed_settled_capture_cut17_data(
                boot,
                connection,
                &self.native,
                &self.records,
            )?),
            None => None,
        };
        if released.is_none()
            && (self.restore_protocol_attempted || self.restore_prepare_admission.is_some())
        {
            return Err(refused());
        }
        if let Some(fresh) = &self.fresh_restore_attempt {
            // A completed Fresh query followed by a partial Prepare is still an
            // active host transaction. Only the actual released Commit closes it.
            if released.is_none() || !self.restore_protocol_attempted {
                return Err(refused());
            }
            let fresh = fresh.try_borrow().map_err(|_| refused())?;
            if fresh.prepare_input.is_none() {
                return Err(refused());
            }
            let (_, _, index) = fresh.publication.completed_parts_data()?;
            let record = self.records.get(index).ok_or_else(refused)?;
            fresh.borrow_completed_prepare_header(connection, record, index)?;
        }
        Ok(released)
    }
}

fn refused() -> ProviderError {
    ProviderError::Correlation("settled Capture17 requires completed original host custody")
}
