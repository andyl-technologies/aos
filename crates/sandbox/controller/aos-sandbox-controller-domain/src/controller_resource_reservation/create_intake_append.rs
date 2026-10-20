//! Borrows the original completed parent and once-entered J capture for one CAS.
//!
//! The exact two-member J successor changes only the Controller subdivision.
//! Original Q04 history, C, its child and the actual terminal native position
//! remain predecessors. This loan creates no current policy or Prepare use.

use super::{
    AccountTransition, ProjectPreparationReservationAttemptV1,
    State, Transition, TransitionOriginal, q04_intake::CreateIntakeBankOriginalsV1,
};
use crate::journal::{Journal, JournalError, JournalTransaction};
use crate::policy_compiler::create_q04::Q04CutIdentityV1;

pub(crate) struct CreateIntakeBankAppendV1<'original> {
    transition: &'original AccountTransition,
    parent: &'original ProjectPreparationReservationAttemptV1,
    entry: CreateIntakeBankOriginalsV1<'original>,
}

impl<'original> CreateIntakeBankAppendV1<'original> {
    pub(super) fn new(
        transition: &'original AccountTransition,
        parent: &'original ProjectPreparationReservationAttemptV1,
        entry: CreateIntakeBankOriginalsV1<'original>,
    ) -> Self {
        Self { transition, parent, entry }
    }

    pub(crate) fn matches_identity(&self, identity: &Q04CutIdentityV1) -> bool {
        self.parent.matches_create_continuation_identity(identity)
    }

    pub(crate) fn require_current(
        &self,
        state: &State,
        transaction: &JournalTransaction,
    ) -> Result<(), JournalError> {
        self.entry.require_current(self.parent, self.transition, state)?;
        if transaction.records().len() != 2 {
            return Err(JournalError::ProtectedBoundary);
        }
        self.transition.require_current(state, transaction)
    }

    pub(crate) fn require_native_position(&self, journal: &Journal) -> Result<(), JournalError> {
        self.entry.require_native_position(self.parent, journal)
    }
}

impl Transition<'_> {
    pub(crate) fn create_intake(&self) -> Option<&CreateIntakeBankAppendV1<'_>> {
        match &self.original {
            TransitionOriginal::CreateIntake(original) => Some(original),
            _ => None,
        }
    }
}

pub(super) fn native_error(error: impl Into<super::ResourceReservationErrorV1>) -> JournalError {
    JournalError::Q04RootOriginal(Box::new(super::q04_resource_error(error)))
}
