//! Preserves the original Hello budget independently of later exchange resets.
//!
//! The initial snapshot is private operational DATA, with no clock-coordinate
//! codec. Only the original Session constructors capture it. Dedicated Bootstrap18
//! construction checks it beside the actual Session and transport frontier.

use super::*;
use crate::operational_time::OperationalDeadline;
use std::mem::size_of;

#[path = "bootstrap_cut/transport.rs"]
mod transport;

#[derive(Clone, Copy)]
pub(super) struct OriginalBootstrapHelloCut(OperationalDeadline);

impl OriginalBootstrapHelloCut {
    pub(super) fn capture(deadline: &ExchangeDeadline) -> Self {
        Self(deadline.original_cut())
    }

    fn authenticate(
        self,
        deadline: &ExchangeDeadline,
    ) -> Result<OperationalDeadline, ProviderError> {
        if deadline.original_cut() != self.0 || self.0.is_expired() {
            return Err(refused());
        }
        Ok(self.0)
    }
}

impl ClientSession {
    /// Checks the unrenewed initial budget and actual unused transport frontier.
    ///
    /// Full selected Bootstrap18 policy, original Hello frame identity and genuine
    /// Source/Birth/funding checks remain with the defining constructor. This
    /// borrowed check changes no timer, sequence, correlation or lifetime credit.
    ///
    /// # Errors
    /// Refuses expiry/reset, a used sequence, absent Hello or changed live SDK.
    pub(in crate::client) fn original_bootstrap_hello_cut_data(
        &self,
    ) -> Result<OperationalDeadline, ProviderError> {
        if self.sequence.get() != 2
            || self.original_response_loss.is_some()
            || self.original_ack_hello.is_none()
        {
            return Err(refused());
        }
        self.connection
            .authenticate_original_bootstrap_frontier_data()?;
        self.bootstrap_hello_cut.authenticate(&self.deadline)
    }

    /// Names the inline snapshot capture before the initial Hello effects.
    pub(in crate::client) fn original_bootstrap_hello_cut_capture_counter_scratch_data() -> usize {
        size_of::<&ExchangeDeadline>()
            + size_of::<OriginalBootstrapHelloCut>()
            + size_of::<OperationalDeadline>()
    }

    /// Names the fixed cut, frontier, actor and registration-read controls.
    pub(in crate::client) fn original_bootstrap_hello_cut_counter_scratch_data() -> usize {
        size_of::<&Self>()
            + size_of::<OriginalBootstrapHelloCut>()
            + size_of::<&ExchangeDeadline>()
            + size_of::<OperationalDeadline>()
            + size_of::<std::time::Duration>()
            + size_of::<Option<std::time::Duration>>()
            + size_of::<Result<OperationalDeadline, ProviderError>>()
            + size_of::<Result<(), ProviderError>>()
            + Connection::<DeadlineStream>::original_bootstrap_frontier_counter_scratch_data()
    }
}

fn refused() -> ProviderError {
    ProviderError::Correlation("original bootstrap Hello cut changed or expired")
}

#[cfg(test)]
#[path = "bootstrap_cut/tests.rs"]
mod tests;
