//! Completes original source retirement under a physical native owner.
//!
//! Running cleanup produces a receipt only after an authenticated, correlated
//! native response. Recovery cleanup retains synchronized bootstrap funding and
//! still requires exhaustive reconciliation before completion. Unavailable
//! includes uncertain accepted work and invalidates the session; no failed
//! exchange is retried or treated as rollback.

use super::{
    BodyIncarnationObservation, Client, Error, PublisherRecoveryContext, PublisherRunningContext,
    invalidate,
};
use crate::{
    host_cache::{
        PublisherCleanupTurn, PublisherRecoveryRestoreTurn, PublisherRecoveryRetirementTurn,
    },
    publisher_local::wire::Operation,
};
use std::{io, sync::Arc};
use terrane_sdk::host::cache::HostDomainLocation;

/// Retains the original source and session after actual final-removal completion.
pub(crate) struct AcknowledgedSourceRetirement {
    session: Arc<Client<HostDomainLocation>>,
    observation: Arc<BodyIncarnationObservation<HostDomainLocation>>,
    request_id: u64,
}

impl AcknowledgedSourceRetirement {
    /// Checks the same original command resources without issuing another RPC.
    ///
    /// # Errors
    /// Refuses another actual session/observation or an absent response sequence.
    pub(crate) fn check(
        &self,
        session: &Arc<Client<HostDomainLocation>>,
        observation: &Arc<BodyIncarnationObservation<HostDomainLocation>>,
    ) -> io::Result<()> {
        if self.request_id == 0
            || !Arc::ptr_eq(session, &self.session)
            || !Arc::ptr_eq(observation, &self.observation)
        {
            return Err(io::Error::other(
                "source cleanup acknowledgement changed custody",
            ));
        }
        Ok(())
    }
}

impl Client<HostDomainLocation> {
    /// Restores an original pending body under funded physical recovery custody.
    ///
    /// This acknowledges namespace effects only. Returned native descriptors are
    /// dropped; canonical inspection and adoption must establish content custody.
    ///
    /// # Errors
    /// Refuses stale physical funding, another Drain or original incarnation,
    /// canonical collisions and failed or uncertain native exchanges.
    pub(crate) fn restore_recovery_body(
        self: &Arc<Self>,
        context: &PublisherRecoveryContext<HostDomainLocation>,
        turn: &mut PublisherRecoveryRestoreTurn<'_>,
    ) -> Result<(), Error> {
        let observation = turn.observation(self, context).map_err(Error::Io)?;
        let mut state = self.lock()?;
        self.require_recovery_context(&state, context)?;
        let payload = observation.checked_payload(self, &state, observation.key())?;
        if let Err(error) = self.exchange_payload(&mut state, Operation::Restore, payload) {
            invalidate(&mut state);
            return Err(error);
        }
        Ok(())
    }

    /// Finishes an expired pending chunk under the funded physical recovery turn.
    ///
    /// The publisher reconstructs missing retirement deadlines conservatively
    /// and checks their actual expiry. Completion grants no adoption or serving
    /// authority and releases no cache funding or measured quota charge.
    ///
    /// # Errors
    /// Refuses changed physical funding, another original Drain or inode,
    /// an unexpired interval and failed or uncertain native exchanges.
    pub(crate) fn finish_recovery_retirement(
        self: &Arc<Self>,
        context: &PublisherRecoveryContext<HostDomainLocation>,
        turn: &mut PublisherRecoveryRetirementTurn<'_>,
    ) -> Result<(), Error> {
        let observation = turn.observation(self, context).map_err(Error::Io)?;
        let mut state = self.lock()?;
        self.require_recovery_context(&state, context)?;
        let payload = observation.checked_payload(self, &state, observation.key())?;
        if let Err(error) = self.exchange_payload(&mut state, Operation::FinishRetirement, payload)
        {
            invalidate(&mut state);
            return Err(error);
        }
        Ok(())
    }

    /// Finishes only the original pending inode under its genuine physical turn.
    ///
    /// The publisher enforces its actual retirement grace and inode token.
    /// Returning this receipt does not release any cache pin, source descriptor
    /// or future hold, nor infer freed kernel allocation.
    ///
    /// # Errors
    /// Refuses foreign/stale funding, a changed native inode, active native grace
    /// and failed/uncertain transport. An exchange failure requires recovery.
    pub(crate) fn finish_source_retirement(
        self: &Arc<Self>,
        context: &PublisherRunningContext,
        turn: &mut PublisherCleanupTurn<'_>,
    ) -> Result<AcknowledgedSourceRetirement, Error> {
        let observation = turn.source_observation(context)?;
        let mut state = self.lock()?;
        self.require_running_context(&state, context)?;
        let payload = observation.checked_payload(self, &state, observation.key())?;
        let received = match self.exchange_payload(&mut state, Operation::FinishRetirement, payload)
        {
            Ok(received) => received,
            Err(error) => {
                invalidate(&mut state);
                return Err(error);
            }
        };
        Ok(AcknowledgedSourceRetirement {
            session: Arc::clone(self),
            observation,
            request_id: received.packet.request_id,
        })
    }
}
