//! Receives Capture17 into its real same-Boot native occurrence.
//!
//! This private prelude retains raw/typed custody and authenticates a newly
//! assigned Source original. It does not select a public route or issue a
//! Capture/Blob effect. Its returned owner must remain alive through the later
//! independent phase debit and real all-ACK publication.

use super::*;
use crate::reference_packet::service::ack_emitter::{NativeAckBoot, OriginalNativeCapture17Read};

impl<S: ProviderStream> PacketEndpoint<S> {
    /// Receives one actually assigned Source Capture or upload original.
    ///
    /// # Errors
    /// Refuses changed Endpoint/restore ancestry, absent actual first owner,
    /// expired deadline, unsupported phase, malformed input or invalid Source
    /// proof. Every failure leaves the same native slot irreversibly spent.
    pub(super) fn receive_original_assigned_capture17_data(
        &mut self,
        deadline: &crate::client::ExchangeDeadline,
    ) -> Result<OriginalNativeCapture17Read, ProviderError> {
        self.ensure_complete_origin()?;
        deadline.remaining()?;
        if !self.held
            || self.records.len() >= EXCHANGES
            || self.capture.is_some()
            || self.capture_allocation_attempt.is_some()
            || self.pending_capture.is_some()
            || self.after_confirmation.is_some()
            || !self.restore_protocol_attempted
        {
            return Err(refused());
        }
        let Some(Transport::Connected(connection)) = self.transport.as_ref() else {
            return Err(refused());
        };
        let boot = self.canonical_ack_boot.as_ref().ok_or_else(refused)?;
        let scope = NativeAckBoot::retain_original_capture17_read_data(
            boot,
            connection,
            &self.native,
            &self.records,
        )?;
        self.restore_commit
            .as_ref()
            .ok_or_else(refused)?
            .authenticate_observation17_host_owners_data(boot, connection)?;
        if let Some(fresh) = &self.fresh_restore_attempt {
            let fresh = fresh.try_borrow().map_err(|_| refused())?;
            if fresh.prepare_input.is_none() {
                return Err(refused());
            }
            let (_, _, index) = fresh.publication.completed_parts_data()?;
            let record = self.records.get(index).ok_or_else(refused)?;
            fresh.borrow_completed_prepare_header(connection, record, index)?;
        }

        let Some(Transport::Connected(connection)) = self.transport.as_mut() else {
            return Err(refused());
        };
        if !connection.receive_original_capture17_data(&scope)? {
            return Err(ProviderError::Frame("Capture17 original peer closed"));
        }
        deadline.remaining()?;
        scope.authenticate_assigned_source_data(connection, &self.native, &self.records)?;
        Ok(scope)
    }
}

fn refused() -> ProviderError {
    ProviderError::Correlation("Capture17 requires the same genuine released Endpoint")
}

/// Names the actual private receive prelude and immutable restore-cut views.
pub(crate) fn native_capture17_endpoint_receive_counter_scratch_data() -> usize {
    use std::mem::size_of;
    size_of::<&mut PacketEndpoint<crate::client::DeadlineStream>>()
        + size_of::<&crate::client::ExchangeDeadline>()
        + size_of::<Result<OriginalNativeCapture17Read, ProviderError>>()
        + size_of::<&Connection<crate::client::DeadlineStream>>()
        + size_of::<&ExchangeRecord>()
        + size_of::<Result<(), ProviderError>>()
        + restore_commit::observation17_host_cut_counter_scratch_data()
}
