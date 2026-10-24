//! Lends an exact original fixed-stage failure while its SAME R guard is held.
//!
//! Diagnostic access performs no native observation, retries no stage and grants
//! no writer, payment, role or currentness capability.

use std::error::Error;
use crate::normal_root::RootReceivingGuardV1;

enum FailureStorageV1<'borrow> {
    Borrowed(&'borrow (dyn Error + 'static)),
    Closed { original: RootReceivingGuardV1<'borrow>,
        stage: super::closed::ClosedFinancialStageV1 },
    SignedController { original: RootReceivingGuardV1<'borrow>,
        stage: super::signed_bound::SignedControllerFinancialStageV1 },
    Outcome { original: RootReceivingGuardV1<'borrow>,
        stage: super::outcome::OutcomeFinancialStageV1 },
    Signed { original: RootReceivingGuardV1<'borrow>, bytes: bool },
}

/// Keeps the original failure borrowed through any required financial-owner guard.
pub struct RootCurrentFailureViewV1<'borrow> { storage: FailureStorageV1<'borrow> }

impl<'borrow> RootCurrentFailureViewV1<'borrow> {
    pub(super) fn borrowed(cause: &'borrow (dyn Error + 'static)) -> Self {
        Self { storage: FailureStorageV1::Borrowed(cause) }
    }

    pub(crate) fn closed(original: RootReceivingGuardV1<'borrow>,
        stage: super::closed::ClosedFinancialStageV1) -> Self {
        Self { storage: FailureStorageV1::Closed { original, stage } }
    }

    pub(crate) fn signed_controller(original: RootReceivingGuardV1<'borrow>,
        stage: super::signed_bound::SignedControllerFinancialStageV1) -> Self {
        Self { storage: FailureStorageV1::SignedController { original, stage } }
    }

    pub(crate) fn signed(original: RootReceivingGuardV1<'borrow>, bytes: bool) -> Self {
        Self { storage: FailureStorageV1::Signed { original, bytes } }
    }

    pub(crate) fn outcome(original: RootReceivingGuardV1<'borrow>,
        stage: super::outcome::OutcomeFinancialStageV1) -> Self {
        Self { storage: FailureStorageV1::Outcome { original, stage } }
    }

    /// Borrows the exact original cause without another read or comparison.
    #[must_use]
    pub fn cause(&self) -> Option<&(dyn Error + 'static)> {
        match &self.storage {
            FailureStorageV1::Borrowed(cause) => Some(*cause),
            FailureStorageV1::Closed { original, stage } => original.original_v1().current_closed_failure_v1(*stage),
            FailureStorageV1::SignedController { original, stage } => original.original_v1().current_signed_controller_failure_v1(*stage),
            FailureStorageV1::Outcome { original, stage } => original.original_v1().current_outcome_failure_v1(*stage),
            FailureStorageV1::Signed { original, bytes } => original.original_v1().current_signed_failure_v1(*bytes),
        }
    }
}
