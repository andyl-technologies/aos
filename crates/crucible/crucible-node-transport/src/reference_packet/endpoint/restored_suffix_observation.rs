//! Publishes a fresh recurring scheduling Observe on the same released socket.
//!
//! The actual published-first native witness selects this closed route. A spent
//! ingress owner precedes receive; current model recount and an independent
//! action debit precede proof production. Only complete ACK publication reopens
//! either the endpoint or native ledger. Other baseline methods remain refused.

use super::*;
use crate::reference_packet::service::ack_emitter::{
    NativeAckBoot, OriginalRestoredSuffixPostObservation,
};

impl<S: ProviderStream> PacketEndpoint<S> {
    /// Authenticates the actual published-first witness before selected receive.
    ///
    /// # Errors
    /// Refuses failed native custody or changed connection/Control provenance.
    pub(super) fn prepare_original_restored_suffix_observation_receive(
        &self,
    ) -> Result<Option<OriginalRestoredSuffixPostObservation>, ProviderError> {
        self.ensure_complete_origin()?;
        let Some(boot) = self.canonical_ack_boot.as_ref() else {
            return Ok(None);
        };
        if !NativeAckBoot::original_restored_suffix_observation_ready_data(boot)? {
            return Ok(None);
        }
        let Some(Transport::Connected(connection)) = self.transport.as_ref() else {
            return Err(refused());
        };
        NativeAckBoot::original_restored_suffix_post_observation_data(
            boot,
            connection,
            &self.native,
            &self.records,
        )
        .map(Some)
    }

    /// Publishes one current scheduling proof under independent native debits.
    ///
    /// # Errors
    /// Refuses expired deadlines, malformed traffic, short native credit, changed
    /// proof/currency or incomplete prefix/ACK publication; the endpoint stays held.
    pub(super) fn receive_and_dispatch_original_restored_suffix_observation(
        &mut self,
        witness: OriginalRestoredSuffixPostObservation,
        deadline: &crate::client::ExchangeDeadline,
    ) -> Result<(), ProviderError> {
        self.ensure_complete_origin()?;
        deadline.remaining()?;
        if !self.held || self.records.len() >= EXCHANGES {
            return Err(refused());
        }
        let Some(Transport::Connected(connection)) = self.transport.as_mut() else {
            return Err(refused());
        };
        let frame =
            usize::try_from(self.authority.limits().frame_bytes.get()).map_err(|_| refused())?;
        let scope = witness.retain_original_observe_ingress_data(
            connection,
            &self.native,
            &self.records,
            frame,
        )?;
        if !connection.receive_original_restored_suffix_observation_data(
            &scope,
            &self.native,
            &self.records,
        )? {
            return Err(ProviderError::Frame(
                "recurring Observe original peer closed",
            ));
        }
        deadline.remaining()?;
        scope.begin_dispatch_data(connection, &self.native, &self.records)?;
        let original = scope.original_data()?;
        {
            let transport = &mut self.transport;
            let sequence = &mut self.next_sequence;
            let credit = &mut self.transport_credit;
            let authority = &self.authority;
            let mut prepare = |reply: &super::super::control::PacketControlReply| {
                prefix::prepare(transport, sequence, credit, authority, &original, reply)
            };
            self.native
                .dispatch_original_restored_suffix_observation_with_preflight(
                    &original,
                    &scope,
                    &mut prepare,
                )?;
        }
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
    ProviderError::Correlation("recurring Observe same released endpoint differs")
}

/// Counts the selected service's concrete Unix-stream publication owners.
pub(crate) fn original_restored_suffix_observation_endpoint_counter_scratch_data() -> usize {
    use std::mem::size_of;
    type NativeTransport = Transport<std::os::unix::net::UnixStream>;
    super::original_endpoint_context_counter_scratch_data()
        + size_of::<OriginalRestoredSuffixPostObservation>()
        + size_of::<Option<OriginalRestoredSuffixPostObservation>>()
        + size_of::<Result<Option<OriginalRestoredSuffixPostObservation>, ProviderError>>()
        + size_of::<
            crate::reference_packet::service::ack_emitter::OriginalRestoredSuffixObserveRead<
                'static,
            >,
        >()
        + size_of::<
            Result<
                crate::reference_packet::service::ack_emitter::OriginalRestoredSuffixObserveRead<
                    'static,
                >,
                ProviderError,
            >,
        >()
        + size_of::<NativeTransport>()
        + size_of::<Option<NativeTransport>>()
        + size_of::<&mut Option<NativeTransport>>()
        + size_of::<&mut u64>()
        + size_of::<&mut usize>()
        + size_of::<&ConnectionAuthority>()
        + size_of::<crate::handshake::Limits>()
        + size_of::<&crate::client::ExchangeDeadline>()
        + size_of::<(Connection<std::os::unix::net::UnixStream>, ExchangeRecord)>()
        + size_of::<
            &mut dyn FnMut(&super::super::control::PacketControlReply) -> Result<(), ProviderError>,
        >()
        + size_of::<Result<(), ProviderError>>()
}
