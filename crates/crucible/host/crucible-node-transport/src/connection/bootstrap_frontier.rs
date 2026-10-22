//! Checks unused original bootstrap transport without allocating or renewing time.
//!
//! The selected Source constructor separately checks full policy, both original
//! Hello frames, opaque recipe/Initial operands and whole caller-owned funding.

use super::*;
use std::mem::size_of;

impl<S: ProviderStream> Connection<S> {
    /// Checks only the current actor, registration and unused post-Hello guard.
    ///
    /// # Errors
    /// Refuses a foreign actor, revoked registration, fenced/wrong endpoint or
    /// any intervening transport or imported continuation.
    pub(crate) fn authenticate_original_bootstrap_frontier_data(
        &self,
    ) -> Result<(), ProviderError> {
        self.protocol_owner.ensure_current()?;
        self.authority.ensure_live()?;
        if self.fenced || self.role != EndpointRole::Controller || !self.guard.unused() {
            return Err(ProviderError::Correlation(
                "original bootstrap frontier changed",
            ));
        }
        Ok(())
    }

    /// Names the actual borrowed frontier, origin and registration controls.
    pub(crate) fn original_bootstrap_frontier_counter_scratch_data() -> usize {
        size_of::<&Self>()
            + size_of::<std::thread::Thread>()
            + size_of::<std::thread::ThreadId>()
            + size_of::<u32>()
            + size_of::<&ConnectionAuthority>()
            + size_of::<std::sync::atomic::Ordering>()
            + size_of::<u64>()
            + size_of::<bool>()
            + size_of::<[Result<(), ProviderError>; 3]>()
    }
}

#[cfg(test)]
#[path = "bootstrap_frontier/tests.rs"]
mod tests;
