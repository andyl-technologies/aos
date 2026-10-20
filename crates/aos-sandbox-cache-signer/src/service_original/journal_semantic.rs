//! Drives the sole raw-COMMIT semantics under the same private Cache F ledger.
//!
//! The private adapter debits actual schema/model peak before Delete/Source/
//! Root/capacity reducers and before final-prefix checks. A failed debit never
//! enters those allocations; it keeps the actual paid native current COMMIT,
//! whole arithmetic cause and independently owed native/F posts resident.

use aos_sandbox_broker::receiving::RepresentationDemandDebitV1 as _;

use std::error::Error;

use aos_sandbox_broker::canonical_journal::{
    CanonicalCommitReadViewV1, CanonicalReplayPrefixReadViewV1,
    coordinator::indexed_replay::{CanonicalIndexedReplayErrorV1, CanonicalIndexedReplayV1},
};
use aos_sandbox_core::{AccountingError, ResourceDimension, ResourceVector};
use aos_sandbox_journal::protected_storage::FileIdentity;
use aos_sandbox_ledger_replay::{cold::ColdReplayRemainderDataV1, geometry};
use aos_sandbox_protocol::domain_ledger::transaction::JournalLimits;

use super::{CacheSignerReceivingClosedV1 as Closed, Common, cause};

mod binding {
    aos_sandbox_ledger_replay::define_cold_replay_binding_v1!();
}

type Mechanical = aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1;

#[derive(Debug, thiserror::Error)]
enum StepError {
    #[error(transparent)]
    Native(#[from] CanonicalIndexedReplayErrorV1),
    #[error("actual Cache replay geometry is refused")]
    Geometry,
    #[error("same-original Cache replay funding is refused")]
    Funding,
    #[error("Cache semantic replay stage is closed")]
    Closed,
}

#[derive(Default)]
struct ReceivingOriginals {
    demand: Option<Result<ResourceVector, Mechanical>>,
    delta: Option<Result<ResourceVector, AccountingError>>,
    debit: Option<Result<(), Closed>>,
    peak: ResourceVector,
}

impl ReceivingOriginals {
    fn reserve_actual(
        &mut self,
        common: &mut Common,
        state: &std::collections::BTreeMap<(aos_sandbox_core::RecordNamespace, Vec<u8>), Vec<u8>>,
        transaction: Option<&aos_sandbox_protocol::domain_ledger::transaction::JournalTransaction>,
    ) -> Result<(), StepError> {
        self.demand = Some(geometry::complete_replay_demand_v1(state, transaction));
        let demand = match self.demand.as_ref() {
            Some(Ok(demand)) => *demand,
            _ => return Err(StepError::Geometry),
        };
        let mut peak = self.peak;
        for dimension in ResourceDimension::ALL {
            peak = peak.with(dimension, peak.get(dimension).max(demand.get(dimension)));
        }
        self.delta = Some(peak.checked_sub(self.peak));
        let delta = match self.delta.as_ref() {
            Some(Ok(delta)) => *delta,
            _ => return Err(StepError::Geometry),
        };
        self.debit = Some(
            common
                .representation
                .as_mut()
                .ok_or(StepError::Closed)?
                .reserve(delta)
                .map_err(|_| Closed),
        );
        if !matches!(self.debit, Some(Ok(()))) {
            return Err(StepError::Funding);
        }
        self.peak = peak;
        Ok(())
    }
}

struct PaidCursor<'cursor, 'file, 'original, 'funding> {
    cursor: &'cursor mut CanonicalIndexedReplayV1<'file, 'original>,
    common: &'funding mut Common,
    receiving: &'funding mut ReceivingOriginals,
}

impl binding::FixedColdNativeStageV1 for PaidCursor<'_, '_, '_, '_> {
    type Error = StepError;

    fn advance_once(&mut self) -> Result<bool, StepError> {
        Ok(self.cursor.advance_once()?)
    }

    fn prepare_semantic_commit_once(&mut self) -> Result<(), StepError> {
        let commit = self.cursor.current_commit().ok_or(StepError::Closed)?;
        self.receiving.reserve_actual(
            self.common,
            commit.prior_state(),
            Some(commit.transaction()),
        )
    }

    fn prepare_semantic_prefix_once(&mut self) -> Result<(), StepError> {
        let prefix = self.cursor.completed_prefix().ok_or(StepError::Closed)?;
        self.receiving
            .reserve_actual(self.common, prefix.state(), None)
    }

    fn current_commit(&self) -> Option<CanonicalCommitReadViewV1<'_>> {
        self.cursor.current_commit()
    }

    fn validate_compaction_once(&mut self) -> Result<(), StepError> {
        Ok(self.cursor.validate_compaction_once()?)
    }

    fn register_and_compare_index_once(&mut self) -> Result<(), StepError> {
        Ok(self.cursor.register_and_compare_index_once()?)
    }

    fn prepare_change_once(&mut self) -> Result<(), StepError> {
        Ok(self.cursor.prepare_change_once()?)
    }

    fn apply_next_record_once(&mut self) -> Result<bool, StepError> {
        Ok(self.cursor.apply_next_record_once()?)
    }

    fn finish_commit_accounting_once(&mut self) -> Result<(), StepError> {
        Ok(self.cursor.finish_commit_accounting_once()?)
    }

    fn finish_commit_once(&mut self) -> Result<(), StepError> {
        Ok(self.cursor.finish_commit_once()?)
    }

    fn completed_prefix(&self) -> Option<CanonicalReplayPrefixReadViewV1<'_>> {
        self.cursor.completed_prefix()
    }

    fn finish_semantic_window_once(&mut self) -> Result<(), StepError> {
        if self.cursor.completed_prefix().is_some() && self.cursor.failure().is_none() {
            Ok(())
        } else {
            Err(StepError::Closed)
        }
    }
}

pub(super) struct CacheJournalSemanticOriginalV1 {
    original: binding::FixedColdSemanticOriginalV1<StepError>,
    receiving: ReceivingOriginals,
    completed: bool,
}

impl CacheJournalSemanticOriginalV1 {
    pub(super) fn new() -> Self {
        Self {
            original: binding::FixedColdSemanticOriginalV1::new(),
            receiving: Default::default(),
            completed: false,
        }
    }

    pub(super) fn fixed_demand_v1() -> Result<ResourceVector, Mechanical> {
        binding::FixedColdSemanticOriginalV1::<StepError>::fixed_demand_v1()
    }

    pub(super) fn observe_once(
        &mut self,
        cursor: &mut CanonicalIndexedReplayV1<'_, '_>,
        identity: FileIdentity,
        limits: JournalLimits,
        common: &mut Common,
    ) -> Result<(), Closed> {
        if self.completed {
            return Err(Closed);
        }
        let mut paid = PaidCursor {
            cursor,
            common,
            receiving: &mut self.receiving,
        };
        let result = self
            .original
            .observe_native_once(&mut paid, identity, limits);
        self.completed = result.is_ok();
        result.map_err(|_| Closed)
    }

    pub(super) fn take_remainder_once(&mut self) -> Option<ColdReplayRemainderDataV1> {
        self.original
            .take_remainder_once()
            .map(binding::move_cold_remainder_data_v1)
    }

    pub(super) fn native_failure_is_selected_v1(&self) -> bool {
        matches!(
            self.original
                .failure()
                .and_then(|cause| cause.downcast_ref::<StepError>()),
            Some(StepError::Native(_))
        )
    }

    pub(super) fn failure<'a>(&'a self, common: &'a Common) -> Option<&'a (dyn Error + 'static)> {
        match self
            .original
            .failure()
            .and_then(|cause| cause.downcast_ref::<StepError>())
        {
            Some(StepError::Geometry) => cause(&self.receiving.demand)
                .or_else(|| cause(&self.receiving.delta))
                .or_else(|| self.original.failure()),
            Some(StepError::Funding) => common
                .representation
                .as_ref()
                .and_then(|ledger| ledger.failure())
                .map(|cause| cause as _)
                .or_else(|| self.original.failure()),
            _ => self.original.failure(),
        }
    }
}
