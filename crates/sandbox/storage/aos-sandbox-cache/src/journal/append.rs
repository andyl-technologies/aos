//! Binds Cache's ordinary native append stages to the shared semantic schedule.
//!
//! Every stage borrows this same private held Cache writer. These five names
//! use ordinary append storage. The finite Q04 initializer lends these same
//! stages into the upper shared schedule, retaining the genuine Root loan and
//! real guard at its full semantic crossing. This core grants neither one.

use aos_sandbox_broker::canonical_journal::CanonicalOrdinaryAppendStageV1;
use aos_sandbox_broker::canonical_journal::coordinator::{
    CanonicalCoordinatorAppendDataV1, CanonicalCoordinatorAppendV1,
};

use super::{CacheMutationGateV1, Journal, JournalError, JournalTransaction};

pub(crate) struct CacheAppendContextV1<'journal, 'transaction> {
    journal: &'journal mut Journal,
    stage: Option<CanonicalOrdinaryAppendStageV1<'transaction>>,
}

impl<'journal, 'transaction> CacheAppendContextV1<'journal, 'transaction> {
    pub(crate) fn new(journal: &'journal mut Journal) -> Self {
        Self {
            journal,
            stage: None,
        }
    }

    pub(crate) fn journal(&self) -> &Journal {
        self.journal
    }

    pub(crate) fn prepare(
        &mut self,
        transaction: &'transaction JournalTransaction,
    ) -> Result<(), JournalError> {
        self.stage = Some(
            self.journal
                .native
                .prepare_append_once(transaction)
                .map_err(|_| JournalError::boundary())?,
        );
        if self.projected_materialized_bytes().is_none() {
            return Err(self.take_failure());
        }
        Ok(())
    }

    pub(crate) fn projected_materialized_bytes(&self) -> Option<usize> {
        self.stage.as_ref()?.projected_materialized_bytes()
    }

    pub(crate) fn coordinates(&mut self) -> Result<(u64, u64), JournalError> {
        let stage = self.stage.as_mut().ok_or(JournalError::boundary())?;
        match self.journal.native.append_coordinates_once(stage) {
            Ok(value) => Ok(value),
            Err(_) => Err(self.take_failure()),
        }
    }

    pub(crate) fn expected_length(&mut self) -> Result<u64, JournalError> {
        let stage = self.stage.as_mut().ok_or(JournalError::boundary())?;
        match self.journal.native.expected_append_length_once(stage) {
            Ok(value) => Ok(value),
            Err(_) => Err(self.take_failure()),
        }
    }

    pub(crate) fn before_cache_append(
        &self,
        gate: &mut CacheMutationGateV1<'_>,
    ) -> Result<Option<Journal>, JournalError> {
        gate.before_append(self.journal)
    }

    pub(crate) fn own_cache_successor(
        &mut self,
        gate: &mut CacheMutationGateV1<'_>,
        transaction: &JournalTransaction,
        sequence: u64,
        bytes: u64,
    ) -> Result<(), JournalError> {
        gate.own_successor(self.journal, transaction, sequence, bytes)
    }

    pub(crate) fn append(&mut self) -> Result<u64, JournalError> {
        let stage = self.stage.as_mut().ok_or(JournalError::boundary())?;
        match self.journal.native.append_prepared_once(stage) {
            Ok(value) => Ok(value),
            Err(_) => Err(self.take_failure()),
        }
    }

    pub(crate) fn apply_next_record(&mut self) -> Result<bool, JournalError> {
        let stage = self.stage.as_mut().ok_or(JournalError::boundary())?;
        match self.journal.native.apply_next_record_once(stage) {
            Ok(value) => Ok(value),
            Err(_) => Err(self.take_failure()),
        }
    }

    pub(crate) fn publish(&mut self) -> Result<(), JournalError> {
        let stage = self.stage.as_mut().ok_or(JournalError::boundary())?;
        match self.journal.native.publish_append_once(stage) {
            Ok(_) => Ok(()),
            Err(_) => Err(self.take_failure()),
        }
    }

    pub(crate) fn mark_q04(&mut self, transaction: &JournalTransaction) {
        self.journal.remainder.q04_lower_history_present |= transaction
            .records()
            .iter()
            .any(aos_sandbox_ledger_replay::semantic_recipe::is_q04_lower_history_record_data_v1);
    }

    pub(crate) fn poison(&mut self) {
        self.journal.native.poison();
    }

    pub(crate) fn finish_ordinary(&mut self) -> Result<(), JournalError> {
        let stage = self.stage.as_mut().ok_or(JournalError::boundary())?;
        match self.journal.native.finish_append_after_posts_once(stage) {
            Ok(()) => Ok(()),
            Err(_) => Err(self.take_failure()),
        }
    }

    pub(crate) fn drop_stage(&mut self) {
        drop(self.stage.take());
    }

    pub(crate) fn into_journal_after_stage_v1(mut self) -> &'journal mut Journal {
        self.drop_stage();
        self.journal
    }

    // These writers preserve the old ordinary temporary-disposal boundary.
    // No captured extractor, permanent sink or selected-role fallback exists.
    fn take_failure(&mut self) -> JournalError {
        self.stage
            .take()
            .and_then(|mut stage| stage.take_ordinary_error_v1().ok().flatten())
            .map(JournalError::from)
            .unwrap_or(JournalError::boundary())
    }
}

impl Journal {
    pub(crate) fn commit(
        &mut self,
        transaction: &JournalTransaction,
    ) -> Result<super::CommitResult, JournalError> {
        self.commit_with_original_cache_gate_v1(transaction, CacheMutationGateV1::Ordinary)
    }

    pub(crate) fn commit_with_retained_cache_gate_v1(
        &mut self,
        transaction: &JournalTransaction,
        gate: &mut super::HeldCacheMutationGateV1,
    ) -> Result<super::CommitResult, JournalError> {
        self.commit_with_original_cache_gate_v1(transaction, CacheMutationGateV1::Retained(gate))
    }

    pub(crate) fn commit_with_original_cache_gate_v1(
        &mut self,
        transaction: &JournalTransaction,
        cache_gate: CacheMutationGateV1<'_>,
    ) -> Result<super::CommitResult, JournalError> {
        self.append_ordinary_v1(transaction, cache_gate)
    }

    fn append_ordinary_v1(
        &mut self,
        transaction: &JournalTransaction,
        mut cache_gate: CacheMutationGateV1<'_>,
    ) -> Result<super::CommitResult, JournalError> {
        let settling = super::policy::validate_before_projection_for_recipe_v1(
            self, transaction, super::policy::CacheTransactionRecipeV1::Ordinary,
        )?;
        let mut context = CacheAppendContextV1::new(self);
        aos_sandbox_broker::run_canonical_semantic_append_v1! {
            ordinary,
            context: context,
            transaction: transaction,
            gate: cache_gate,
            boundary: JournalError::boundary(),
            coordinates: (materialized_bytes, commit_sequence, following_sequence, durable_bytes),
            preflight: {
                super::policy::validate_after_coordinates(context.journal(), transaction, following_sequence)?;
                let expected_length = context.expected_length()?;
                super::policy::validate_after_expected_length(
                    context.journal(), transaction, settling, materialized_bytes, expected_length,
                )?;
            },
            final_crossing: {},
            durable_check: {},
            published: {
                context.mark_q04(transaction);
            },
            completed: {
                Ok(super::CommitResult { commit_sequence, durable_bytes })
            },
        }
    }
}
