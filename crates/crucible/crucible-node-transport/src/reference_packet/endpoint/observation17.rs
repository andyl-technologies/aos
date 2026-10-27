//! Publishes the distinct signed Observe17 producer through ordinary transport.
//!
//! This private consumer is intentionally not selected by Endpoint's receive
//! entry. The early selected17 refusal remains until the host Window/Source
//! issuer and released17 adopter conjunction is installed and qualified.

use super::*;
use crate::reference_packet::service::ack_emitter::NativeAckBoot;

impl<S: ProviderStream> PacketEndpoint<S> {
    fn authenticate_observation17_host_cut_data(
        &self,
        connection: &Connection<S>,
        boot: &Rc<std::cell::RefCell<NativeAckBoot>>,
    ) -> Result<(), ProviderError> {
        self.ensure_complete_origin()?;
        if self.capture.is_some()
            || self.capture_allocation_attempt.is_some()
            || self.pending_capture.is_some()
            || self.after_confirmation.is_some()
            || !self.restore_protocol_attempted
        {
            return Err(refused());
        }
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
        Ok(())
    }

    /// Runs the actual Initial15-ancestry signed17 receive/producer/publication.
    ///
    /// This private route is connected to the native scope, retained Control
    /// producer, exact Observe2 prefix and actual all-ACK publication. Its public
    /// dispatcher remains closed; neither this method nor transport completion
    /// constructs a host Window claim or a cold17 released-adopter witness.
    ///
    /// # Errors
    /// Refuses foreign/stale Endpoint ownership, expired deadlines, another
    /// native ancestry, unsupported input, MAC/current/model mismatch, short
    /// rows or incomplete native/transport publication. The endpoint stays held.
    pub(super) fn receive_and_dispatch_original_observation17_data(
        &mut self,
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
        let scope = NativeAckBoot::retain_original_observation17_read_data(
            boot,
            connection,
            &self.native,
            &self.records,
        )?;
        self.authenticate_observation17_host_cut_data(connection, boot)?;
        let Some(Transport::Connected(connection)) = self.transport.as_mut() else {
            return Err(refused());
        };
        if !connection.receive_original_observation17_data(&scope)? {
            return Err(ProviderError::Frame(
                "signed Observe17 original peer closed",
            ));
        }
        deadline.remaining()?;
        scope.authenticate_source_data(connection)?;
        let projection = scope.produce_data(
            connection,
            &mut self.native,
            &self.records,
            self.next_sequence,
        )?;
        // Its exact requested replacement bank is part of the same independent
        // action row. Any refusal keeps the spent original/produced proof/cache.
        self.records.try_reserve_exact(1).map_err(|_| {
            ProviderError::ResourceExhausted("signed Observe17 completed record slot")
        })?;
        {
            let transport = &mut self.transport;
            let sequence = &mut self.next_sequence;
            let credit = &mut self.transport_credit;
            let authority = &self.authority;
            scope.with_prepared_reply_data(&self.native, |original, reply| {
                prefix::prepare_with_restored_observation17_projection_storage_data(
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
        scope.retain_prepared_terminal_data(exchange.record())?;
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
        scope.complete_publication_data(connection, &self.native, &self.records)?;
        self.held = false;
        Ok(())
    }
}

fn refused() -> ProviderError {
    ProviderError::Correlation("signed Observe17 same released Endpoint differs")
}

/// Names the actual native Endpoint publication and host-cut fixed owners.
///
/// Scope/Control/transport-geometry visitors have separate defining getters;
/// these are independently added to the same new ingress/action reservation.
pub(crate) fn native_observation17_endpoint_counter_scratch_data() -> usize {
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
        + size_of::<std::slice::Iter<'static, ExchangeRecord>>()
        + restore_commit::observation17_host_cut_counter_scratch_data()
}
