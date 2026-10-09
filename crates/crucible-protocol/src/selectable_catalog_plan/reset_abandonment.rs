//! Separates reset-abandoned requests from guest-consumed replies.
//!
//! Schema five carries both ledgers through capture, fork and restore. Reset
//! abandonment consumes the same finite request allowance and replay watermark
//! while preserving frozen declarations and genuine completed-reply counts.

use super::*;

impl SelectablePlanContinuation {
    /// Restores the explicit abandoned ledger into this continuation.
    ///
    /// The caller owns admission for the supplied map. An empty ledger is the
    /// cold/default state, not compatibility with an older encoded schema.
    ///
    /// # Errors
    /// Refuses invalid identifiers, zero counters, unknown registrations,
    /// excessive counts, inconsistent watermarks or a stale pending request.
    pub fn with_abandoned_requests(
        mut self,
        abandoned: BTreeMap<String, u64>,
        last_sequence: Option<u64>,
    ) -> Result<Self, SelectableCatalogPlanError> {
        if abandoned.len() > SELECTABLE_CATALOG_PLAN_MAX_DECLARATIONS {
            return Err(SelectableCatalogPlanError::CountTooLarge {
                field: "abandoned",
                actual: abandoned.len(),
                maximum: SELECTABLE_CATALOG_PLAN_MAX_DECLARATIONS,
            });
        }
        let mut total = 0_u64;
        for (identifier, count) in &abandoned {
            validate_selectable_identifier("abandoned_selectable", identifier)?;
            if !self.registered.contains(identifier) {
                return Err(SelectableCatalogPlanError::UnknownIdentifier {
                    field: "abandoned",
                    identifier: identifier.clone(),
                });
            }
            if *count == 0 {
                return Err(SelectableCatalogPlanError::InvalidContinuation {
                    reason: "abandoned request counter is zero",
                });
            }
            total = total
                .checked_add(*count)
                .ok_or(SelectableCatalogPlanError::CountOverflow)?;
        }
        if (total == 0) != last_sequence.is_none()
            || (total != 0 && self.phase != SelectablePlanPhase::Frozen)
            || last_sequence.is_some_and(|last| Some(last) == self.last_completed_request_sequence)
        {
            return Err(SelectableCatalogPlanError::InvalidContinuation {
                reason: "abandoned request ledger has an inconsistent phase or watermark",
            });
        }
        self.abandoned_requests = abandoned;
        self.total_abandoned_requests = total;
        self.last_abandoned_request_sequence = last_sequence;
        let attempted = self.attempted_requests()?;
        if attempted > SELECTABLE_CATALOG_PLAN_MAX_REQUESTS {
            return Err(SelectableCatalogPlanError::RequestLimitExceeded {
                field: "attempted_requests",
                actual: attempted,
                maximum: SELECTABLE_CATALOG_PLAN_MAX_REQUESTS,
            });
        }
        if self.pending.as_ref().is_some_and(|pending| {
            self.last_attempt_sequence()
                .is_some_and(|last| pending.request.sequence() <= last)
        }) {
            return Err(SelectableCatalogPlanError::InvalidContinuation {
                reason: "pending request does not advance the attempted watermark",
            });
        }
        Ok(self)
    }

    /// Returns reset-abandoned counts in canonical identifier order.
    #[must_use]
    pub const fn abandoned_requests(&self) -> &BTreeMap<String, u64> {
        &self.abandoned_requests
    }

    /// Returns the last sequence abandoned by a completed reset.
    #[must_use]
    pub const fn last_abandoned_request_sequence(&self) -> Option<u64> {
        self.last_abandoned_request_sequence
    }

    /// Returns the number of reset-abandoned requests.
    #[must_use]
    pub const fn total_abandoned_requests(&self) -> u64 {
        self.total_abandoned_requests
    }

    pub(super) fn last_attempt_sequence(&self) -> Option<u64> {
        self.last_completed_request_sequence
            .max(self.last_abandoned_request_sequence)
    }

    pub(super) fn attempted_requests(&self) -> Result<u64, SelectableCatalogPlanError> {
        self.total_completed_requests
            .checked_add(self.total_abandoned_requests)
            .ok_or(SelectableCatalogPlanError::CountOverflow)
    }

    pub(super) fn attempts_for(&self, identifier: &str) -> Result<u64, SelectableCatalogPlanError> {
        self.completed_requests
            .get(identifier)
            .copied()
            .unwrap_or(0)
            .checked_add(
                self.abandoned_requests
                    .get(identifier)
                    .copied()
                    .unwrap_or(0),
            )
            .ok_or(SelectableCatalogPlanError::CountOverflow)
    }
}

impl SelectableCatalogPlan {
    /// Abandons the exact old request after authentic reset completion.
    ///
    /// The caller must first verify the real reset-completion observation and
    /// prepay any counter-map growth. This transition grants neither authority
    /// nor completion evidence. It never writes a guest reply or increments a
    /// genuine completed-reply counter.
    ///
    /// # Errors
    /// Refuses absent or mismatched pending identity and exhausted/overflowing
    /// request accounting. Validation finishes before continuation mutation.
    pub fn apply_reset_abandonment(
        &mut self,
        old: &SelectablePlanPendingRequest,
    ) -> Result<(), SelectableCatalogPlanError> {
        if self.continuation.pending.as_ref() != Some(old) {
            return Err(SelectableCatalogPlanError::InvalidTransition {
                reason: "reset abandonment differs from the exact pending request",
            });
        }
        self.validate_attempt_limits()?;
        let total = self
            .continuation
            .total_abandoned_requests
            .checked_add(1)
            .ok_or(SelectableCatalogPlanError::CountOverflow)?;
        let identifier = old.request.selectable_id();
        let count = self
            .continuation
            .abandoned_requests
            .get(identifier)
            .copied()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(SelectableCatalogPlanError::CountOverflow)?;

        self.continuation
            .abandoned_requests
            .insert(identifier.to_owned(), count);
        self.continuation.total_abandoned_requests = total;
        self.continuation.last_abandoned_request_sequence = Some(old.request.sequence());
        self.continuation.pending = None;
        Ok(())
    }

    pub(super) fn validate_attempt_limits(&self) -> Result<(), SelectableCatalogPlanError> {
        let continuation = &self.continuation;
        let total = continuation
            .attempted_requests()?
            .checked_add(u64::from(continuation.pending.is_some()))
            .ok_or(SelectableCatalogPlanError::CountOverflow)?;
        if total > self.limits.total_requests {
            return Err(SelectableCatalogPlanError::RequestLimitExceeded {
                field: "total_requests",
                actual: total,
                maximum: self.limits.total_requests,
            });
        }
        for identifier in &continuation.registered {
            let pending = continuation
                .pending
                .as_ref()
                .is_some_and(|pending| pending.request.selectable_id() == identifier);
            let count = continuation
                .attempts_for(identifier)?
                .checked_add(u64::from(pending))
                .ok_or(SelectableCatalogPlanError::CountOverflow)?;
            if count > self.limits.requests_per_selectable {
                return Err(SelectableCatalogPlanError::RequestLimitExceeded {
                    field: "requests_per_selectable",
                    actual: count,
                    maximum: self.limits.requests_per_selectable,
                });
            }
        }
        Ok(())
    }
}
