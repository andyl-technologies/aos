//! Lends the actual current-purpose receiving context to the sole Cold recipe.
//!
//! This module has no opener, account, role factory or optional-context branch.
//! The enclosing native purpose retains admission and every independently owed
//! post. The real context runs its original COMMIT/EOF gates before semantic
//! allocation, including the exact accepted-history and suffix comparisons.

mod binding {
    aos_sandbox_ledger_replay::define_cold_replay_binding_v1!();
}

use std::error::Error;
use std::mem::size_of;

use aos_sandbox_broker::canonical_journal::{
    CanonicalCommitReadViewV1, CanonicalJournalMechanicalErrorV1,
    CanonicalReplayPrefixReadViewV1,
};
use aos_sandbox_broker::canonical_journal::coordinator::indexed_replay::{
    CanonicalIndexedReplayErrorV1, CanonicalIndexedReplayV1,
};
use aos_sandbox_journal::protected_storage::FileIdentity;
use aos_sandbox_ledger_replay::cold::{ColdReplayClosedV1, ColdReplayRemainderDataV1};
use aos_sandbox_protocol::domain_ledger::transaction::JournalLimits;

use crate::native::root_current::readonly_receiving::RootCurrentReadonlyReceivingContextV1;
use super::super::error::RootReadonlyErrorV1;
use binding::{FixedColdNativeStageV1, FixedColdSemanticOriginalV1};

pub(super) struct CurrentRoleReplayOriginalV1 {
    original: FixedColdSemanticOriginalV1<RootReadonlyErrorV1>,
}

impl CurrentRoleReplayOriginalV1 {
    pub(super) fn new() -> Self {
        Self { original: FixedColdSemanticOriginalV1::new() }
    }

    // Family backing remains in the actual per-state semantic admission. Empty
    // construction does not buy an unconditional second family allocation.
    pub(super) fn receiving_construction_bytes_v1() -> Option<usize> {
        FixedColdSemanticOriginalV1::<RootReadonlyErrorV1>::receiving_construction_bytes_v1()?
            .checked_add(size_of::<CurrentNativeV1<'_, '_, '_, '_, '_, '_>>().checked_mul(2)?)?
            .checked_add(size_of::<Result<(), ()>>().checked_mul(2)?)?
            .checked_add(size_of::<Result<(), ColdReplayClosedV1>>().checked_mul(2)?)?
            .checked_add(size_of::<Result<(), RootReadonlyErrorV1>>().checked_mul(2)?)?
            .checked_add(size_of::<(
                CanonicalIndexedReplayErrorV1,
                CanonicalJournalMechanicalErrorV1,
                RootReadonlyErrorV1,
            )>().checked_mul(2)?)?
            .checked_add(size_of::<(
                Option<CanonicalCommitReadViewV1<'_>>,
                Option<CanonicalReplayPrefixReadViewV1<'_>>,
                (u64, u64),
            )>().checked_mul(2)?)
    }

    pub(super) fn observe_once(
        &mut self,
        cursor: &mut CanonicalIndexedReplayV1<'_, '_>,
        identity: FileIdentity,
        limits: JournalLimits,
        receiving: &mut RootCurrentReadonlyReceivingContextV1<'_, '_, '_>,
    ) -> Result<(), ColdReplayClosedV1> {
        let mut native = CurrentNativeV1 { cursor, receiving };
        self.original.observe_native_once(&mut native, identity, limits)
            .map_err(|_| ColdReplayClosedV1)
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.original.failure()
    }

    pub(super) fn source_failure_cause_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.original.source_failure_cause_v1()
    }

    pub(super) fn native_failure_is_selected_v1(&self) -> bool {
        self.original.native_failure_is_selected_v1()
    }

    pub(super) fn take_remainder_once(&mut self) -> Option<ColdReplayRemainderDataV1> {
        self.original.take_remainder_once().map(binding::move_cold_remainder_data_v1)
    }
}

// The context is a concrete native purpose borrower, never a callback or a
// caller-provided payer. Its admission/frontier slots remain on that same
// purpose original. In particular, absence cannot select a no-op hook.
struct CurrentNativeV1<'turn, 'file, 'cursor, 'borrow, 'original, 'data> {
    cursor: &'turn mut CanonicalIndexedReplayV1<'file, 'cursor>,
    receiving: &'turn mut RootCurrentReadonlyReceivingContextV1<'borrow, 'original, 'data>,
}

fn native_error(cause: CanonicalIndexedReplayErrorV1) -> RootReadonlyErrorV1 {
    match cause {
        CanonicalIndexedReplayErrorV1::Native(cause) => RootReadonlyErrorV1::from(
            CanonicalJournalMechanicalErrorV1::from_ordinary_native_v1(cause),
        ),
        // The actual same index original retains the deeper typed cause.
        CanonicalIndexedReplayErrorV1::Closed => RootReadonlyErrorV1::ProtectedBoundary,
    }
}

impl FixedColdNativeStageV1 for CurrentNativeV1<'_, '_, '_, '_, '_, '_> {
    type Error = RootReadonlyErrorV1;

    fn prepare_semantic_commit_once(&mut self) -> Result<(), Self::Error> {
        let commit = self.cursor.current_commit()
            .ok_or(RootReadonlyErrorV1::ProtectedBoundary)?;
        let (begin_sequence, begin_offset) = commit.begin_position();
        self.receiving.observe_native_commit(
            commit.transaction(), begin_sequence, commit.commit_sequence(),
            begin_offset, commit.coordinates().offset,
        )?;
        self.receiving.before_semantic_replay(commit.prior_state(), Some(commit.transaction()))?;
        Ok(())
    }

    fn prepare_semantic_prefix_once(&mut self) -> Result<(), Self::Error> {
        let prefix = self.cursor.completed_prefix()
            .ok_or(RootReadonlyErrorV1::ProtectedBoundary)?;
        self.receiving.before_semantic_replay(prefix.state(), None)?;
        let coordinates = prefix.coordinates();
        self.receiving.finish_native_replay(
            coordinates.durable_next_sequence, coordinates.durable_end,
        )?;
        Ok(())
    }

    fn advance_once(&mut self) -> Result<bool, Self::Error> {
        self.cursor.advance_once().map_err(native_error)
    }

    fn current_commit(&self) -> Option<CanonicalCommitReadViewV1<'_>> {
        self.cursor.current_commit()
    }

    fn validate_compaction_once(&mut self) -> Result<(), Self::Error> {
        self.cursor.validate_compaction_once().map_err(native_error)
    }

    fn register_and_compare_index_once(&mut self) -> Result<(), Self::Error> {
        self.cursor.register_and_compare_index_once().map_err(native_error)
    }

    fn prepare_change_once(&mut self) -> Result<(), Self::Error> {
        self.cursor.prepare_change_once().map_err(native_error)
    }

    fn apply_next_record_once(&mut self) -> Result<bool, Self::Error> {
        self.cursor.apply_next_record_once().map_err(native_error)
    }

    fn finish_commit_accounting_once(&mut self) -> Result<(), Self::Error> {
        self.cursor.finish_commit_accounting_once().map_err(native_error)
    }

    fn finish_commit_once(&mut self) -> Result<(), Self::Error> {
        self.cursor.finish_commit_once().map_err(native_error)
    }

    fn completed_prefix(&self) -> Option<CanonicalReplayPrefixReadViewV1<'_>> {
        self.cursor.completed_prefix()
    }

    fn finish_semantic_window_once(&mut self) -> Result<(), Self::Error> {
        self.cursor.completed_prefix().ok_or(RootReadonlyErrorV1::ProtectedBoundary)?;
        Ok(())
    }
}
