//! Compares ordinary Hold rows or the actual exclusive Git-prefix original.
//!
//! Decoded rows are historical DATA. Exclusive enrollment additionally needs
//! the same writer's complete Genesis/birth replay and final native bookend.

use aos_sandbox_model::format::git_upload_enrollment::{
    GitCoverageBirthFieldsV1, GitCoverageFenceFieldsV1,
};
use aos_sandbox_protocol::cache_state::hold_state::{
    CachePolicyDecodedStateDataV1 as Decoded,
    CachePolicyHoldReadbackDataV1 as Readback,
    CachePolicyHoldStateDataV1 as State,
};
use aos_sandbox_protocol::domain_ledger::cache_policy_hold::CachePolicyHoldV1;

use super::super::{Journal, JournalError};

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum CachePolicyGateStateV1 {
    Ordinary(State),
    Exclusive(CacheGitCoverageObservationV1),
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct CacheGitCoverageObservationV1 {
    birth: GitCoverageBirthFieldsV1,
    fence: GitCoverageFenceFieldsV1,
    prefix: [u8; 32],
    commit_sequence: u64,
}

impl CacheGitCoverageObservationV1 {
    pub(crate) fn enrollment(self) -> [u8; 32] {
        self.birth.enrollment
    }

    pub(crate) fn catalog(self) -> [u8; 32] {
        self.birth.catalog
    }

    pub(crate) fn original_coordinates(
        self,
    ) -> (GitCoverageBirthFieldsV1, GitCoverageFenceFieldsV1, [u8; 32], u64) {
        (self.birth, self.fence, self.prefix, self.commit_sequence)
    }
}

impl CachePolicyGateStateV1 {
    pub(super) fn is_exclusive(self) -> bool {
        matches!(self, Self::Exclusive(_))
    }

    pub(super) fn require_new_mutation(self) -> Result<(), JournalError> {
        match self {
            Self::Ordinary(state)
                if !state.hold.is_some_and(|hold| hold.is_held())
                    && state.v8_pending.is_none() => Ok(()),
            _ => Err(JournalError::boundary()),
        }
    }
}

pub(super) fn current_full_state(journal: &mut Journal) -> Result<Readback, JournalError> {
    journal.require_no_cache_held_history_v1()?;
    let authority = journal.claim_cache_authority_v1()?;
    aos_sandbox_protocol::cache_state::hold_state::decode_full_state(authority.records()?)
        .map_err(aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1::from)
        .map_err(JournalError::from)
}

pub(in crate::journal) fn current_state(journal: &mut Journal) -> Result<State, JournalError> {
    let state = current_full_state(journal)?;
    if state.q04_pending.is_some() {
        return Err(JournalError::boundary());
    }
    Ok(state.legacy)
}

pub(super) fn current(journal: &mut Journal) -> Result<Option<CachePolicyHoldV1>, JournalError> {
    let state = current_full_state(journal)?;
    // Keep the original signer observation of a held Q04 row. A released
    // pending row remains closed to the ordinary unheld/mutation check.
    if state.q04_pending.as_ref().is_some_and(|marker| !marker.is_held()) {
        return Err(JournalError::boundary());
    }
    Ok(state.legacy.hold)
}

pub(super) fn current_gate_state(journal: &mut Journal) -> Result<CachePolicyGateStateV1, JournalError> {
    journal.require_no_cache_held_history_v1()?;
    let decoded = {
        let authority = journal.claim_cache_authority_v1()?;
        aos_sandbox_protocol::cache_state::hold_state::decode_gate_state(authority.records()?)
            .map_err(aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1::from)?
    };
    match decoded {
        Decoded::Ordinary(state) => {
            if state.q04_pending.is_some() {
                return Err(JournalError::boundary());
            }
            Ok(CachePolicyGateStateV1::Ordinary(state.legacy))
        }
        Decoded::Exclusive { birth, fence } => {
            let mut native = journal.cache_coverage_native_prefix_v1()
                .map_err(|error| JournalError::NativePrefix(Box::new(error)))?;
            let (transaction, commit_sequence) = native.last_commit()
                .ok_or(JournalError::boundary())?;
            if native.counts() != (2, 3)
                || transaction != fence.transaction
                || commit_sequence != birth.commit_sequence
            {
                return Err(JournalError::boundary());
            }
            let prefix = native.prefix_digest();
            native.recheck()?;
            Ok(CachePolicyGateStateV1::Exclusive(CacheGitCoverageObservationV1 {
                birth, fence, prefix, commit_sequence,
            }))
        }
    }
}
