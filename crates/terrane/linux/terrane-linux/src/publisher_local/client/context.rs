//! Captures actual successful drain custody without claiming recovery completion.
//!
//! Opaque contexts retain the original session and root guard. They cannot be
//! constructed from caller-selected nonces or epochs and do not authorize Resume.

use std::sync::Arc;
use terrane_sdk::host::cache::HostReadLocation;

use super::{Client, Error, State};

/// Retains the exact session and successful drain epoch for native recovery work.
///
/// This proves only the acknowledged publisher barrier. Cache reconstruction,
/// durable pins and completion require their separate genuine native producer.
pub(crate) struct PublisherRecoveryContext<L: HostReadLocation> {
    session: Arc<Client<L>>,
    epoch: u64,
}

impl<L: HostReadLocation> Client<L> {
    /// Captures current acknowledged drain custody without issuing another Drain.
    ///
    /// # Errors
    ///
    /// Rejects poisoned client state, an absent acknowledged barrier or stale
    /// retained roots. This never creates completed-recovery authority.
    pub(crate) fn recovery_context(self: &Arc<Self>) -> Result<PublisherRecoveryContext<L>, Error> {
        let state = self.lock()?;
        self.require_drained(&state)?;
        self.layout.recheck()?;
        Ok(PublisherRecoveryContext {
            session: Arc::clone(self),
            epoch: state.recovery_epoch,
        })
    }

    /// Rechecks actual session identity and the currently acknowledged barrier.
    ///
    /// # Errors
    ///
    /// Rejects another session/root/incarnation, an uncertain exchange, another
    /// drain epoch, poisoned client state or stale retained roots.
    pub(crate) fn check_recovery_context(
        &self,
        context: &PublisherRecoveryContext<L>,
    ) -> Result<(), Error> {
        let state = self.lock()?;
        self.require_recovery_context(&state, context)?;
        self.layout.recheck()?;
        Ok(())
    }

    pub(super) fn require_recovery_context(
        &self,
        state: &State,
        context: &PublisherRecoveryContext<L>,
    ) -> Result<(), Error> {
        self.require_drained(state)?;
        if !std::ptr::eq(self, context.session.as_ref())
            || self.cache_incarnation != context.session.cache_incarnation
            || !Arc::ptr_eq(&self.layout, &context.session.layout)
            || state.recovery_epoch != context.epoch
        {
            return Err(Error::Invalid(
                "publisher recovery context belongs to another session or drain",
            ));
        }
        Ok(())
    }
}
