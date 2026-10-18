//! Transfers an actual admitted inline source under the funded Running turn.
//!
//! The inspection reply enters its registered job slot before verification.
//! Native/byte checks run after releasing the RPC mutex. Retirement accepts only
//! that actual same-response inode observation and keeps physical custody on error.

use super::{
    Client, Error, PeerPublishedObject, RequestPayload, invalidate,
    recovery::BodyIncarnationObservation, running::PublisherRunningContext,
};
use crate::{
    host_cache::PublisherRunningTurn,
    publisher_local::{socket::ReceivedPacket, wire::Operation},
};
use terrane::host::cache::HostDomainLocation;

impl Client<HostDomainLocation> {
    /// Inspects only the original standalone inode of this funded publication.
    ///
    /// # Errors
    /// Refuses stale funding, another source, occupied reply custody, failed
    /// transport, or an inode/access/byte mismatch. Uncertain replies stay owned.
    pub(crate) fn inspect_inline_transfer(
        &self,
        body: &PeerPublishedObject<HostDomainLocation>,
        context: &PublisherRunningContext,
        turn: &mut PublisherRunningTurn<'_>,
        reply: &mut Option<ReceivedPacket>,
    ) -> Result<BodyIncarnationObservation<HostDomainLocation>, Error> {
        turn.check_replacement(context, body)?;
        let claim = body.claim();
        let key = turn.transfer_key(context, claim)?;
        if reply.is_some() {
            return Err(Error::Invalid(
                "inline transfer reply slot already occupied",
            ));
        }
        let mut state = self.lock()?;
        self.require_running_context(&state, context)?;
        let received = match self.exchange_payload(
            &mut state,
            Operation::InspectBody,
            RequestPayload {
                body: Some(key.clone()),
                ..Default::default()
            },
        ) {
            Ok(received) => received,
            Err(error) => {
                invalidate(&mut state);
                return Err(error);
            }
        };
        *reply = Some(received);
        let observation = match reply
            .as_ref()
            .ok_or(Error::Invalid("transfer reply absent"))
            .and_then(|received| {
                self.observation(&state, key.clone(), &received.packet.body_incarnation)
            }) {
            Ok(observation) => observation,
            Err(error) => {
                invalidate(&mut state);
                return Err(error);
            }
        };
        drop(state);

        // This checks actual embedded/native custody. The RPC mutex must not
        // remain held underneath it, even though dispatch stays exclusive.
        let verified = (|| {
            let received = reply
                .as_ref()
                .ok_or(Error::Invalid("transfer reply absent"))?;
            if received.files.len() != 1 {
                return Err(Error::Invalid("transfer inspection descriptor count"));
            }
            let file = received
                .files
                .first()
                .ok_or(Error::Invalid("transfer descriptor absent"))?;
            turn.check_transfer_reply(context, claim, &key, file)?;
            Ok(())
        })();
        if let Err(error) = verified {
            let mut state = self.lock()?;
            invalidate(&mut state);
            return Err(error);
        }
        Ok(observation)
    }

    /// Retires only the actual inspected source after its sealed replacement exists.
    ///
    /// The actual publisher owns the pending rename and durable retirement lease.
    /// This RPC never finishes deletion or releases source holds/descriptors.
    ///
    /// # Errors
    /// Refuses foreign/stale funding or observation, failed physical retirement,
    /// and uncertain transport. Any failure requires actual owner recovery.
    pub(crate) fn retire_inline_transfer(
        &self,
        body: &PeerPublishedObject<HostDomainLocation>,
        context: &PublisherRunningContext,
        turn: &mut PublisherRunningTurn<'_>,
        observation: &BodyIncarnationObservation<HostDomainLocation>,
    ) -> Result<(), Error> {
        turn.check_replacement(context, body)?;
        let claim = body.claim();
        let key = turn.transfer_key(context, claim)?;
        let mut state = self.lock()?;
        self.require_running_context(&state, context)?;
        let payload = observation.checked_payload(self, &state, &key)?;
        if let Err(error) = self.exchange_payload(&mut state, Operation::Retire, payload) {
            invalidate(&mut state);
            return Err(error);
        }
        Ok(())
    }
}
