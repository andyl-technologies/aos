//! Dispatches the actual boot-owned restoration activation on its same socket.
//!
//! The endpoint remains sticky-held through authentication, proof preparation,
//! physical release and the complete publication suffix. The boot retains the
//! moved request and partial typed owners on any refusal or unwind.

use super::*;
use crate::reference_packet::service::ack_emitter::NativeAckBoot;

impl<S: ProviderStream> PacketEndpoint<S> {
    pub(super) fn dispatch_selected_restoration_activation(
        &mut self,
        request: Envelope,
        deadline: &crate::client::ExchangeDeadline,
    ) -> Result<(), ProviderError> {
        self.ensure_complete_origin()?;
        deadline.remaining()?;
        if !self.held || self.records.len() >= EXCHANGES {
            return Err(refused());
        }
        let boot = self.canonical_ack_boot.as_ref().ok_or_else(refused)?;
        let Some(Transport::Connected(connection)) = self.transport.as_ref() else {
            return Err(refused());
        };
        let permit =
            NativeAckBoot::retain_restoration_activation(boot, connection, request, &self.native)?;
        // Mark the one dispatch before borrowing its retained original. No
        // subsequent refusal can return this slot to an unattempted state.
        permit.begin_dispatch_data()?;
        let original = permit.original_data()?;
        {
            let transport = &mut self.transport;
            let sequence = &mut self.next_sequence;
            let credit = &mut self.transport_credit;
            let authority = &self.authority;
            let mut prepare = |reply: &super::super::control::PacketControlReply| {
                prefix::prepare(transport, sequence, credit, authority, &original, reply)
            };
            self.native
                .dispatch_original_restoration_activation_with_preflight(
                    &original,
                    &permit,
                    &mut prepare,
                )?;
        }
        let Some(Transport::Prepared(exchange, acknowledgements)) = self.transport.as_mut() else {
            return Err(refused());
        };
        // WorldActivate has already prepared the full held=false proof before
        // the real physical release. Only now can its original prefix publish.
        exchange.publish(&mut |sent, received| acknowledgements.validate(sent, received))?;
        drop(original);
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
        permit.complete_publication(connection, self.records.last().ok_or_else(refused)?)?;
        self.held = false;
        Ok(())
    }
}

fn refused() -> ProviderError {
    ProviderError::Correlation("selected native restoration activation endpoint held")
}

impl<S: ProviderStream> PacketEndpoint<S> {
    pub(super) fn dispatch_selected_restoration_upload(
        &mut self,
        request: Envelope,
        deadline: &crate::client::ExchangeDeadline,
    ) -> Result<(), ProviderError> {
        self.ensure_complete_origin()?;
        deadline.remaining()?;
        if !self.held || self.records.len() >= EXCHANGES {
            return Err(refused());
        }
        let boot = self.canonical_ack_boot.as_ref().ok_or_else(refused)?;
        let Some(Transport::Connected(connection)) = self.transport.as_ref() else {
            return Err(refused());
        };
        let permit =
            NativeAckBoot::retain_restoration_upload(boot, connection, request, &self.native)?;
        // A dedicated exact raw bank is admitted by the signed ordinal. The
        // generic receiver's 64 KiB content limit remains unchanged.
        let reply = permit.prepare_content_reply_data(&mut self.native)?;
        let original = permit.original_data()?;
        self.prepare(&original, &reply)?;
        let Some(Transport::Prepared(exchange, acknowledgements)) = self.transport.as_mut() else {
            return Err(refused());
        };
        exchange.publish(&mut |sent, received| acknowledgements.validate(sent, received))?;
        drop(original);
        let Some(Transport::Prepared(exchange, _)) = self.transport.take() else {
            return Err(refused());
        };
        let (connection, record) = exchange.into_parts();
        self.records.push(record);
        self.transport = Some(Transport::Connected(connection));
        deadline.remaining()?;
        let Some(Transport::Connected(connection)) = self.transport.as_ref() else {
            return Err(refused());
        };
        permit.complete_publication(connection, self.records.last().ok_or_else(refused)?)?;
        self.held = false;
        Ok(())
    }
}
