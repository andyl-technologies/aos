//! Opaque operational deadlines for the native ARM control and custody paths.
//!
//! The shared provider clock exposes only expiry/remaining allowance. No raw
//! host coordinate becomes a modeled event, a receipt field or a launch binding.

use std::time::Duration;

// crucible-lint: allow host-nondeterminism-state -- This private wait budget imports only opaque operational expiry, never a raw modeled clock.
use crate::{ProviderError, operational_time::OperationalDeadline};

// crucible-lint: allow host-nondeterminism-state -- This nonserialized capsule owns one original operational wait deadline.
pub(crate) struct HostBudget(OperationalDeadline);

impl HostBudget {
    pub(crate) fn after(duration: Duration) -> Result<Self, ProviderError> {
        // crucible-lint: allow host-nondeterminism-state -- The original transport or retirement wait receives one nonrenewable host allowance.
        OperationalDeadline::after(duration)
            .map(Self)
            .ok_or(ProviderError::Frame(
                "ARM operational deadline cannot be represented",
            ))
    }

    pub(crate) fn is_expired(&self) -> bool {
        self.0.is_expired()
    }
}
