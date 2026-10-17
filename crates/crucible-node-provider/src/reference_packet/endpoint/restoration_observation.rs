//! Drives one separately funded restored observation on the same released socket.
//!
//! The positive released witness selects a restriction before receive. Its once
//! read slot precedes the reader, and the independent MAC/row permit precedes
//! Control proof production. No sticky restoration flag is reset and no generic
//! dispatch fallback is created for a restored target.

use super::*;
use crate::reference_packet::service::ack_emitter::{
    NativeAckBoot, OriginalRestorationObservationRead, OriginalRestorationReleaseState,
};

impl<S: ProviderStream> PacketEndpoint<S> {
    pub(super) fn prepare_original_restoration_observation_receive(
        &self,
    ) -> Result<Option<OriginalRestorationObservationRead>, ProviderError> {
        self.ensure_complete_origin()?;
        let Some(boot) = self.canonical_ack_boot.as_ref() else {
            return Ok(None);
        };
        let Some(Transport::Connected(connection)) = self.transport.as_ref() else {
            return Err(refused());
        };
        match NativeAckBoot::original_restoration_release_data(
            boot,
            connection,
            &self.native,
            &self.records,
        )? {
            // Pending continues only the prior sticky restoration dispatcher.
            // It supplies neither ordinary receive nor a missing-data fallback.
            OriginalRestorationReleaseState::Pending => Ok(None),
            OriginalRestorationReleaseState::Released(released) => {
                let read = NativeAckBoot::retain_restoration_observation_read_data(
                    released,
                    connection,
                    &self.native,
                    &self.records,
                )?;
                Ok(Some(read))
            }
        }
    }

    pub(super) fn receive_and_dispatch_original_restoration_observation(
        &mut self,
        read: OriginalRestorationObservationRead,
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
        if !connection.receive_original_restoration_observation_data(&read)? {
            return Err(ProviderError::Frame(
                "restored Observe original peer closed",
            ));
        }
        deadline.remaining()?;
        let permit = read.verify_data(connection, &self.native, &self.records)?;
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
                .dispatch_original_restoration_observation_with_preflight(
                    &original,
                    &permit,
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
        permit.complete_publication_data(connection, &self.native, &self.records)?;
        self.held = false;
        Ok(())
    }
}

fn refused() -> ProviderError {
    ProviderError::Correlation("restored Observe same released endpoint differs")
}
