//! Keeps the actual fixed Hold writer as Cache's mutation interlock.
//!
//! Ordinary checks open the existing fixed role under its original allocation
//! policy. Retained and resident checks borrow the same writer, two actual
//! target identities and exact own-successor seals through the append boundary.

use std::path::Path;

use aos_sandbox_protocol::cache_state::fixed_journals::CacheJournalRecipeRoleV1;

use super::{Journal, JournalError, JournalLimits};

mod retained;
pub(super) mod state;
mod transitions;
pub(crate) use transitions::HeldCachePolicyObservationV1;

pub(crate) use retained::{
    BorrowedCacheMutationGateV1, CacheMutationGateV1, HeldCacheMutationGateV1,
};
use state::{CachePolicyGateStateV1, current_gate_state};
pub(crate) use state::CacheGitCoverageObservationV1;

pub(super) const NAME: &str = aos_sandbox_protocol::cache_state::fixed_journals::CACHE_HOLD_BASENAME_V1;

pub(super) fn hold_limits() -> JournalLimits {
    CacheJournalRecipeRoleV1::Hold.limits_v1()
}

fn check_unheld(journal: &Journal) -> Result<(), JournalError> {
    let _guard = mutation_guard(journal)?;
    Ok(())
}

fn mutation_guard(journal: &Journal) -> Result<Option<Journal>, JournalError> {
    let Some((directory, uid)) = &journal.cache_policy_gate else {
        return Ok(None);
    };
    #[cfg(not(test))]
    journal.require_protected_location(
        directory,
        journal.read_view().protected_name().ok_or(JournalError::boundary())?,
        *uid,
        journal.limits(),
    )?;
    let mut hold = Journal::open_cache_hold_ordinary_v1(directory, *uid)?;
    if state::current(&mut hold)?.is_some_and(|hold| hold.is_held()) {
        return Err(JournalError::boundary());
    }
    Ok(Some(hold))
}

impl Journal {
    pub(crate) fn cache_policy_hold_limits() -> JournalLimits {
        hold_limits()
    }

    pub(crate) fn read_cache_policy_hold_at(
        directory: &Path,
        uid: u32,
    ) -> Result<Option<aos_sandbox_protocol::domain_ledger::cache_policy_hold::CachePolicyHoldV1>, JournalError> {
        state::current(&mut Self::open_cache_hold_ordinary_v1(directory, uid)?)
    }
}
