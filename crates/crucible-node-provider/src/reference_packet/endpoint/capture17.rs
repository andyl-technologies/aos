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

impl PacketEndpoint<crate::client::DeadlineStream> {
    /// Publishes one Source-authenticated assigned upload through ordinary IO.
    ///
    /// The caller passes the actual raw-first retained scope; no second read or
    /// synthetic request is performed. This private method does not select the
    /// public17 route, issue a Window claim or authenticate a cold17 adopter.
    ///
    /// # Errors
    /// Refuses another Endpoint/occurrence/phase, expired deadline, short full
    /// prospective row, real Blob failure or incomplete terminal publication.
    /// Every initialized raw/native/receiver/transport partial remains owned.
    pub(super) fn dispatch_original_assigned_capture17_upload_data(
        &mut self,
        scope: OriginalNativeCapture17Read,
        deadline: &crate::client::ExchangeDeadline,
    ) -> Result<(), ProviderError> {
        self.ensure_complete_origin()?;
        deadline.remaining()?;
        if !self.held || self.records.len() >= EXCHANGES {
            return Err(refused());
        }
        let Some(Transport::Connected(connection)) = self.transport.as_ref() else {
            return Err(refused());
        };
        let boot = self.canonical_ack_boot.as_ref().ok_or_else(refused)?;
        self.restore_commit
            .as_ref()
            .ok_or_else(refused)?
            .authenticate_observation17_host_owners_data(boot, connection)?;
        let projection = scope.prepare_assigned_upload17_data(
            connection,
            &self.uploads,
            &self.native,
            &self.records,
            self.next_sequence,
        )?;
        scope.execute_assigned_upload17_data(&mut self.uploads)?;
        self.records.try_reserve_exact(1).map_err(|_| {
            ProviderError::ResourceExhausted("Capture17 upload completed record slot")
        })?;
        {
            let transport = &mut self.transport;
            let sequence = &mut self.next_sequence;
            let credit = &mut self.transport_credit;
            let authority = &self.authority;
            scope.with_prepared_upload17_reply_data(|original, reply| {
                prefix::prepare_with_capture17_upload_projection_storage_data(
                    transport,
                    sequence,
                    credit,
                    authority,
                    original,
                    reply,
                    &projection,
                )
            })?;
        }
        let Some(Transport::Prepared(exchange, acknowledgements)) = self.transport.as_mut() else {
            return Err(refused());
        };
        scope.retain_upload17_terminal_data(exchange.record())?;
        exchange.publish(&mut |sent, received| acknowledgements.validate(sent, received))?;
        let Some(Transport::Prepared(exchange, _)) = self.transport.take() else {
            return Err(refused());
        };
        let (connection, record) = exchange.into_parts();
        self.records.push(record);
        self.transport = Some(Transport::Connected(connection));
        let Some(Transport::Connected(connection)) = self.transport.as_ref() else {
            return Err(refused());
        };
        deadline.remaining()?;
        scope.complete_upload17_publication_data(connection, &self.native, &self.records)?;
        self.held = false;
        Ok(())
    }
}

/// Names actual private assigned-upload Endpoint and publication loop headers.
pub(crate) fn native_capture17_upload_endpoint_counter_scratch_data() -> usize {
    use std::mem::size_of;
    type NativeTransport = Transport<crate::client::DeadlineStream>;
    size_of::<&mut PacketEndpoint<crate::client::DeadlineStream>>()
        + size_of::<NativeTransport>()
        + size_of::<&mut Option<NativeTransport>>()
        + size_of::<&mut u64>()
        + size_of::<&mut usize>()
        + size_of::<&ConnectionAuthority>()
        + size_of::<&crate::client::ExchangeDeadline>()
        + size_of::<(Connection<crate::client::DeadlineStream>, ExchangeRecord)>()
        + size_of::<Result<(), ProviderError>>()
        + restore_commit::observation17_host_cut_counter_scratch_data()
        + prefix::native_capture17_upload_prefix_counter_scratch_data()
}
