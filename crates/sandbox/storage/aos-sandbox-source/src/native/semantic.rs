//! Binds the sole cold semantic recipe to the actual C-funded Source cursor.
//!
//! Both private semantic preparation stages charge complete actual-row demand
//! to the same opening's Source original before any family growth. The native
//! parser/index/COMMIT bodies and pure semantic sequence remain shared engines.

use aos_sandbox_broker::source_receiving::{SourceNativeErrorV1, SourceSemanticReceivingLoanV1};

aos_sandbox_ledger_replay::define_cold_replay_binding_v1!();

/// Distinguishes a native stop from the same original's semantic debit refusal.
#[derive(Debug, thiserror::Error)]
pub(crate) enum SourcePaidReplayErrorV1<E: std::error::Error + 'static = SourceNativeErrorV1> {
    #[error(transparent)]
    Native(#[from] CanonicalIndexedReplayErrorV1),
    #[error(transparent)]
    Geometry(#[from] JournalError),
    #[error(transparent)]
    Receiving(E),
}

/// Selects only a private actual C-construction or S-readonly funding borrower.
///
/// This crate-private boundary cannot be implemented by a caller or supplied
/// through a public role constructor. The native parser and semantic driver
/// remain the same for both actual owners.
pub(crate) trait SourceReplayFundingV1 {
    type Error: std::error::Error + 'static;

    fn prepare_commit(
        &mut self,
        commit: aos_sandbox_broker::canonical_journal::CanonicalCommitReadViewV1<'_>,
    ) -> Result<(), SourcePaidReplayErrorV1<Self::Error>>;

    fn prepare_prefix(
        &mut self,
        prefix: aos_sandbox_broker::canonical_journal::CanonicalReplayPrefixReadViewV1<'_>,
    ) -> Result<(), SourcePaidReplayErrorV1<Self::Error>>;


}

impl SourceReplayFundingV1 for SourceSemanticReceivingLoanV1<'_> {
    type Error = SourceNativeErrorV1;

    fn prepare_commit(
        &mut self,
        commit: aos_sandbox_broker::canonical_journal::CanonicalCommitReadViewV1<'_>,
    ) -> Result<(), SourcePaidReplayErrorV1> {
        let complete = aos_sandbox_ledger_replay::geometry::complete_replay_demand_v1(
            commit.prior_state(), Some(commit.transaction()),
        )?;
        self.require_dynamic_complete_v1(complete).map_err(SourcePaidReplayErrorV1::Receiving)
    }

    fn prepare_prefix(
        &mut self,
        prefix: aos_sandbox_broker::canonical_journal::CanonicalReplayPrefixReadViewV1<'_>,
    ) -> Result<(), SourcePaidReplayErrorV1> {
        let complete = aos_sandbox_ledger_replay::geometry::complete_replay_demand_v1(
            prefix.state(), None,
        )?;
        self.require_dynamic_complete_v1(complete).map_err(SourcePaidReplayErrorV1::Receiving)
    }
}

/// Keeps the actual disjoint native cursor and same-opening financial loan.
pub(crate) struct SourcePaidReplayV1<'file, 'original, F: SourceReplayFundingV1> {
    native: CanonicalIndexedReplayV1<'file, 'original>,
    receiving: F,
}

impl<'file, 'original, F: SourceReplayFundingV1> SourcePaidReplayV1<'file, 'original, F> {
    pub(crate) fn new(
        native: CanonicalIndexedReplayV1<'file, 'original>,
        receiving: F,
    ) -> Self {
        Self { native, receiving }
    }
}

impl<F: SourceReplayFundingV1> FixedColdNativeStageV1 for SourcePaidReplayV1<'_, '_, F> {
    type Error = SourcePaidReplayErrorV1<F::Error>;

    fn advance_once(&mut self) -> Result<bool, Self::Error> {
        Ok(self.native.advance_once()?)
    }

    fn prepare_semantic_commit_once(&mut self) -> Result<(), Self::Error> {
        let commit = self.native.current_commit().ok_or(JournalError::ProtectedBoundary)?;
        self.receiving.prepare_commit(commit)
    }

    fn prepare_semantic_prefix_once(&mut self) -> Result<(), Self::Error> {
        let prefix = self.native.completed_prefix().ok_or(JournalError::ProtectedBoundary)?;
        self.receiving.prepare_prefix(prefix)
    }

    fn current_commit(&self)
        -> Option<aos_sandbox_broker::canonical_journal::CanonicalCommitReadViewV1<'_>>
    {
        self.native.current_commit()
    }

    fn validate_compaction_once(&mut self) -> Result<(), Self::Error> {
        Ok(self.native.validate_compaction_once()?)
    }

    fn register_and_compare_index_once(&mut self) -> Result<(), Self::Error> {
        Ok(self.native.register_and_compare_index_once()?)
    }

    fn prepare_change_once(&mut self) -> Result<(), Self::Error> {
        Ok(self.native.prepare_change_once()?)
    }

    fn apply_next_record_once(&mut self) -> Result<bool, Self::Error> {
        Ok(self.native.apply_next_record_once()?)
    }

    fn finish_commit_accounting_once(&mut self) -> Result<(), Self::Error> {
        Ok(self.native.finish_commit_accounting_once()?)
    }

    fn finish_commit_once(&mut self) -> Result<(), Self::Error> {
        Ok(self.native.finish_commit_once()?)
    }

    fn completed_prefix(&self)
        -> Option<aos_sandbox_broker::canonical_journal::CanonicalReplayPrefixReadViewV1<'_>>
    {
        self.native.completed_prefix()
    }

    fn finish_semantic_window_once(&mut self) -> Result<(), Self::Error> {
        if self.native.completed_prefix().is_none() || self.native.failure().is_some() {
            Err(CanonicalIndexedReplayErrorV1::Closed.into())
        } else {
            Ok(())
        }
    }
}

pub(super) type SourceSemanticOriginalV1 = FixedColdSemanticOriginalV1<SourcePaidReplayErrorV1>;

/// Selects the actual lower native capture only for a native stage stop.
pub(super) fn selected_native_cause(original: &SourceSemanticOriginalV1) -> bool {
    original.failure().and_then(|cause| cause.downcast_ref::<SourcePaidReplayErrorV1>())
        .is_some_and(|cause| matches!(cause, SourcePaidReplayErrorV1::Native(_)))
}

/// Selects the actual same-opening debt only for its own debit stop.
pub(super) fn selected_receiving_cause(original: &SourceSemanticOriginalV1) -> bool {
    original.failure().and_then(|cause| cause.downcast_ref::<SourcePaidReplayErrorV1>())
        .is_some_and(|cause| matches!(cause, SourcePaidReplayErrorV1::Receiving(_)))
}

/// Prices the actual private paid-cursor and external remainder moves as bytes.
pub(super) fn fixed_demand_v1()
    -> Result<aos_sandbox_model::ResourceVector, JournalError>
{
    let invalid = || JournalError::LimitExceeded("Source paid semantic replay geometry");
    let extra = std::mem::size_of::<SourcePaidReplayV1<'_, '_, SourceSemanticReceivingLoanV1<'_>>>().checked_mul(2)
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<aos_sandbox_ledger_replay::cold::ColdReplayRemainderDataV1>().checked_mul(2)?))
        .and_then(|bytes| u64::try_from(bytes).ok()).ok_or_else(invalid)?;
    SourceSemanticOriginalV1::fixed_demand_v1()?
        .checked_add(aos_sandbox_model::ResourceVector::ZERO.with(
            aos_sandbox_model::ResourceDimension::MemoryBytes, extra,
        ))
        .map_err(|_| invalid())
}
