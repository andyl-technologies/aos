//! Retains the exact original Q04 child through its sole terminal bank append.
//!
//! This loan can originate only from the parent holding the moved co-issuance,
//! eight native results and seven posts. It selects the existing terminal CAS;
//! it does not clear policy history, authorize another operation or issue funds.

use super::{
    AccountTransition, Q04TerminalOriginalsV1, State, Transition, TransitionOriginal, bank,
    q04_resource_error,
};
use crate::journal::{Journal, JournalError, JournalTransaction};
use crate::policy_compiler::create_q04::Q04CutIdentityV1;

/// Borrows the actual retained child for the one existing terminal successor.
///
/// Fields and construction remain private to the Native resource-bank owner.
/// Decoded terminal rows and ordinary account mutations cannot create this loan.
pub(crate) struct Q04TerminalBankAppendV1<'original> {
    transition: &'original AccountTransition,
    retained: Q04TerminalOriginalsV1<'original>,
}

impl<'original> Q04TerminalBankAppendV1<'original> {
    pub(super) fn new(
        transition: &'original AccountTransition,
        retained: Q04TerminalOriginalsV1<'original>,
    ) -> Self {
        Self {
            transition,
            retained,
        }
    }

    pub(crate) fn matches_identity(&self, identity: &Q04CutIdentityV1) -> bool {
        self.retained.original.binding.matches_q04_cut(identity)
    }

    /// Rechecks complete retained outcomes and the exact terminal bank members.
    ///
    /// # Errors
    /// Rejects a missing or failed original, changed co-issuance, nonterminal
    /// mutation, changed charge, extra member or differing account predecessor.
    pub(crate) fn require_current(
        &self,
        state: &State,
        transaction: &JournalTransaction,
    ) -> Result<(), JournalError> {
        if self
            .retained
            .native
            .iter()
            .any(|result| !matches!(result, Some(Ok(_))))
            || self
                .retained
                .posts
                .iter()
                .any(|result| !matches!(result, Some(Ok(()))))
            || self.retained.original.crossing_failure().is_some()
            || self.retained.original.last_clock_failure().is_some()
            || self.transition.original_clock != Some(self.retained.original.original_clock)
            || self.transition.previous_claim
                != Some(self.retained.original.binding.native_fields().use_claim)
            || self.transition.claim.native_fields().state != bank::ClaimState::Committed
            || self.transition.child.is_some()
            || self.transition.preparation.is_some()
        {
            return Err(JournalError::ProtectedBoundary);
        }

        let terminal = self
            .transition
            .terminal
            .ok_or(JournalError::ProtectedBoundary)?;
        self.retained
            .original
            .require_last_clock()
            .map_err(native_error)?;
        self.retained
            .original
            .binding
            .require_replayed(state)
            .map_err(native_error)?;
        terminal
            .require_predecessor(state, self.transition.history())
            .map_err(native_error)?;
        self.transition.require_current(state, transaction)
    }

    /// Rechecks the same physical names and last returned native position.
    ///
    /// This repeats immediately before the unchanged kernel clock crossing.
    ///
    /// # Errors
    /// Rejects changed native names, additional history, truncation or differing
    /// returned positions. Native causes remain nested in their original type.
    pub(crate) fn require_native_position(&self, journal: &Journal) -> Result<(), JournalError> {
        let terminal = self
            .transition
            .terminal
            .ok_or(JournalError::ProtectedBoundary)?;
        self.retained
            .original
            .require_readback(journal)
            .map_err(native_error)?;
        self.retained
            .original
            .require_last_clock()
            .map_err(native_error)?;
        journal.require_q04_terminal_preappend_positions_v1(terminal, self.retained.native)
    }
}

impl Transition<'_> {
    pub(crate) fn q04_terminal(&self) -> Option<&Q04TerminalBankAppendV1<'_>> {
        match &self.original {
            TransitionOriginal::Q04Terminal(original) => Some(original),
            _ => None,
        }
    }
}

fn native_error(error: impl Into<super::ResourceReservationErrorV1>) -> JournalError {
    JournalError::Q04RootOriginal(Box::new(q04_resource_error(error)))
}
