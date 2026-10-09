//! Settles authenticated reset abandonment without forging guest replies.
//!
//! The live reset callback supplies the retained catalog token only after the
//! matching physical reset completes. Admission and capture preserve separate
//! completed and abandoned ledgers under the same original request limits.

use super::*;

impl SelectableCatalog {
    /// Abandons the exact retained request after correlated reset completion.
    ///
    /// The caller verifies reset completion and prepays counter-map growth.
    /// This state transition is neither reset evidence nor admission authority.
    /// Frozen declarations and completed-reply accounting remain unchanged.
    ///
    /// # Errors
    ///
    /// Returns an error for an absent or different catalog token or overflowing
    /// accounting. All validation finishes before the pending token is removed.
    pub fn abandon_request_after_reset(
        &mut self,
        pending: &SelectablePendingRequest,
    ) -> Result<(), SelectableCatalogError> {
        let retained = self
            .pending
            .as_ref()
            .ok_or(SelectableCatalogError::NoPendingRequest)?;
        if retained != pending {
            return Err(SelectableCatalogError::PendingRequestMismatch);
        }

        let next_total = self
            .total_abandoned_requests
            .checked_add(1)
            .ok_or(SelectableCatalogError::RequestCountOverflow)?;
        let identifier = retained.request.selectable_id();
        let next_selectable = self
            .abandoned_requests
            .get(identifier)
            .copied()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(SelectableCatalogError::RequestCountOverflow)?;
        let sequence = retained.request.sequence();

        // Allocate the ledger key before clearing the real retained token.
        self.abandoned_requests
            .insert(identifier.to_owned(), next_selectable);
        self.total_abandoned_requests = next_total;
        self.last_abandoned_request_sequence = Some(sequence);
        self.pending = None;
        self.pending_boundary_sealed = false;
        Ok(())
    }

    /// Returns reset-abandoned counts in canonical identifier order.
    #[must_use]
    pub const fn abandoned_request_counts(&self) -> &BTreeMap<String, u64> {
        &self.abandoned_requests
    }

    /// Returns the number of reset-abandoned requests.
    #[must_use]
    pub const fn total_abandoned_requests(&self) -> u64 {
        self.total_abandoned_requests
    }

    /// Returns the last reset-abandoned sequence without changing reply history.
    #[must_use]
    pub const fn last_abandoned_request_sequence(&self) -> Option<u64> {
        self.last_abandoned_request_sequence
    }
}

#[cfg(test)]
mod tests;
