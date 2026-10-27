//! Correlates encoded cache transitions with original physical-owner custody.
//!
//! Inspection retains the actual reply before checking its descriptors. Retire,
//! Restore and FinishRetirement use the existing registered wire operations;
//! only an exclusive native owner turn can select the original allocation.

use super::{
    BodyIncarnationObservation, Client, Error, PublisherRunningContext, RequestPayload, invalidate,
};
use crate::{
    host_cache::PublisherEncodedCacheTurn,
    publisher_local::{
        socket::ReceivedPacket,
        wire::{BodyKey, Operation},
    },
};
use std::{io, sync::Arc};
use terrane_sdk::host::cache::HostDomainLocation;

/// Retains an actual Retire acknowledgment for the inspected original unit.
pub(crate) struct EncodedCacheReceipt {
    session: Arc<Client<HostDomainLocation>>,
    observation: Arc<BodyIncarnationObservation<HostDomainLocation>>,
    request_id: u64,
}

impl EncodedCacheReceipt {
    /// Checks the original peer, allocation key and actual acknowledgment.
    ///
    /// # Errors
    /// Refuses another peer or allocation and an absent response sequence.
    pub(crate) fn check_original(
        &self,
        session: &Arc<Client<HostDomainLocation>>,
        key: &BodyKey,
    ) -> io::Result<()> {
        if self.request_id == 0
            || !Arc::ptr_eq(session, &self.session)
            || self.observation.key() != key
        {
            return Err(io::Error::other(
                "encoded retirement changed original custody",
            ));
        }
        Ok(())
    }
}

/// Retains a correlated restoration or final-removal acknowledgment.
pub(crate) struct EncodedCacheCompletion {
    original: Arc<EncodedCacheReceipt>,
    operation: Operation,
    request_id: u64,
}

impl EncodedCacheCompletion {
    /// Checks an actual final-removal reply without inferring descriptor closure.
    ///
    /// # Errors
    /// Refuses another original acknowledgment, operation or absent sequence.
    pub(crate) fn check_removed(&self, original: &Arc<EncodedCacheReceipt>) -> io::Result<()> {
        self.check(original, Operation::FinishRetirement)
    }

    /// Checks an actual restoration reply before original stamp refresh.
    ///
    /// # Errors
    /// Refuses another original acknowledgment, operation or absent sequence.
    pub(crate) fn check_restored(&self, original: &Arc<EncodedCacheReceipt>) -> io::Result<()> {
        self.check(original, Operation::Restore)
    }

    fn check(&self, original: &Arc<EncodedCacheReceipt>, operation: Operation) -> io::Result<()> {
        if self.request_id == 0
            || self.operation != operation
            || !Arc::ptr_eq(original, &self.original)
        {
            return Err(io::Error::other(
                "encoded completion changed original acknowledgment",
            ));
        }
        Ok(())
    }
}

impl Client<HostDomainLocation> {
    /// Inspects the original encoded allocation under physical exclusion.
    ///
    /// # Errors
    /// Refuses stale Running custody, occupied reply storage, failed exchanges
    /// and returned descriptors that differ from the original admitted inodes.
    pub(crate) fn inspect_cached_encoded(
        self: &Arc<Self>,
        context: &PublisherRunningContext,
        turn: &mut PublisherEncodedCacheTurn<'_>,
        reply: &mut Option<ReceivedPacket>,
    ) -> Result<Arc<BodyIncarnationObservation<HostDomainLocation>>, Error> {
        let key = turn.key(context, Operation::InspectBody, None)?;
        if reply.is_some() {
            return Err(Error::Invalid("encoded inspection reply already retained"));
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
        let received = reply
            .as_ref()
            .ok_or(Error::Invalid("encoded inspection reply absent"))?;
        let observation = match self.observation(&state, key, &received.packet.body_incarnation) {
            Ok(observation) => Arc::new(observation),
            Err(error) => {
                invalidate(&mut state);
                return Err(error);
            }
        };
        drop(state);
        if let Err(error) = turn.check_received(context, &received.files) {
            let mut state = self.lock()?;
            invalidate(&mut state);
            return Err(error.into());
        }
        Ok(observation)
    }

    /// Retires only the actually inspected unit under its original exclusive turn.
    ///
    /// # Errors
    /// Refuses another unit, stale Running custody and failed or uncertain exchanges.
    pub(crate) fn retire_cached_encoded(
        self: &Arc<Self>,
        context: &PublisherRunningContext,
        turn: &mut PublisherEncodedCacheTurn<'_>,
        observation: &Arc<BodyIncarnationObservation<HostDomainLocation>>,
    ) -> Result<EncodedCacheReceipt, Error> {
        let key = turn.key(context, Operation::Retire, None)?;
        let mut state = self.lock()?;
        self.require_running_context(&state, context)?;
        let payload = observation.checked_payload(self, &state, &key)?;
        let received = match self.exchange_payload(&mut state, Operation::Retire, payload) {
            Ok(received) => received,
            Err(error) => {
                invalidate(&mut state);
                return Err(error);
            }
        };
        Ok(EncodedCacheReceipt {
            session: Arc::clone(self),
            observation: Arc::clone(observation),
            request_id: received.packet.request_id,
        })
    }

    /// Restores or finishes the original encoded allocation through its retained reply.
    ///
    /// # Errors
    /// Refuses another physical phase, original receipt or peer and uncertain exchanges.
    pub(crate) fn transition_cached_encoded(
        self: &Arc<Self>,
        context: &PublisherRunningContext,
        turn: &mut PublisherEncodedCacheTurn<'_>,
        original: &Arc<EncodedCacheReceipt>,
        operation: Operation,
    ) -> Result<EncodedCacheCompletion, Error> {
        let key = turn.key(context, operation, Some(original))?;
        original.check_original(self, &key)?;
        let mut state = self.lock()?;
        self.require_running_context(&state, context)?;
        let payload = original.observation.checked_payload(self, &state, &key)?;
        let received = match self.exchange_payload(&mut state, operation, payload) {
            Ok(received) => received,
            Err(error) => {
                invalidate(&mut state);
                return Err(error);
            }
        };
        Ok(EncodedCacheCompletion {
            original: Arc::clone(original),
            operation,
            request_id: received.packet.request_id,
        })
    }
}
