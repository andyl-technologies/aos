//! Owns physical Source original replay and challenge-currentness barriers.
//!
//! Saved-state comparisons belong to the canonical Source DATA cache. These
//! private adapters preserve actual native observations and error projection.

use std::sync::Arc;
use aos_sandbox_source_provider_ledger::ledger::source_capacity::OriginalSourceChallengeDataV5;
use super::{
    State, SourceOriginalAdmissionDataV5, SourceOriginalAdmissionInputV5,
    SourceOriginalChallengeHistoryViewV5, SourceCapacityUnionComparisonDataV5,
    compare_source_original_admission_data_v5, invalid,
    challenge::SourceOriginalChallengeCheckpointV5,
};
use super::super::{JournalError, JournalLimits, JournalTransaction, RecordNamespace};
#[cfg(test)]
use super::owner_views;

pub use aos_sandbox_ledger_replay::replay::source_original::cache::SourceOriginalPhysicalCutV5;
use aos_sandbox_ledger_replay::replay::source_original::cache::{
    SourceOriginalReplayDataV5, admission_payload_bound, prospective_payload_bytes, retirement_width,
};

#[derive(Clone, Default)]
#[repr(transparent)]
pub(in crate::provider_journal) struct SourceOriginalReplayCacheV5 {
    data: SourceOriginalReplayDataV5<super::super::JournalAuthorityInstance>,
}

impl std::ops::Deref for SourceOriginalReplayCacheV5 {
    type Target = SourceOriginalReplayDataV5<super::super::JournalAuthorityInstance>;

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl std::ops::DerefMut for SourceOriginalReplayCacheV5 {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.data
    }
}

impl SourceOriginalReplayCacheV5 {
    pub(in crate::provider_journal) fn original_release_resident_copy_bytes_v1(
        &self,
    ) -> Result<usize, JournalError> {
        self.data.original_release_resident_copy_bytes_v1().map_err(JournalError::from)
    }

    pub(in crate::provider_journal) fn needs_closure(&self) -> bool {
        self.data.needs_closure()
    }

    pub(in crate::provider_journal) fn has_dependencies(&self) -> bool {
        self.data.has_dependencies()
    }

    pub(super) fn origins(&self) -> &[SourceOriginalAdmissionDataV5] {
        self.data.origins()
    }

    pub(super) fn cuts(&self) -> &[SourceOriginalPhysicalCutV5] {
        self.data.cuts()
    }

    pub(super) fn prospective_challenge_checkpoint(&self) -> Option<usize> {
        self.data.prospective_challenge_checkpoint()
    }

    pub(super) fn retain_challenges(
        &mut self,
        view: &SourceOriginalChallengeHistoryViewV5<'_>,
    ) -> Result<(), JournalError> {
        self.challenges = Some(view.retained_witness()?);
        Ok(())
    }

    pub(in crate::provider_journal) fn validate_challenges(
        &self,
        view: &SourceOriginalChallengeHistoryViewV5<'_>,
    ) -> Result<(), JournalError> {
        let witness = self.challenges.as_ref()
            .ok_or(JournalError::ProtectedBoundary)?;
        view.validate_retained_witness(witness)
    }

    pub(in crate::provider_journal) fn compare_cached(
        &self,
        state: &State,
        transaction: Option<&JournalTransaction>,
        limits: JournalLimits,
    ) -> Result<SourceCapacityUnionComparisonDataV5, JournalError> {
        self.data.compare_cached(state, transaction, limits).map_err(JournalError::from)
    }

    pub(in crate::provider_journal) fn preview_transaction(
        &self,
        state: &State,
        transaction: &JournalTransaction,
        limits: JournalLimits,
    ) -> Result<(Self, SourceCapacityUnionComparisonDataV5), JournalError> {
        self.data.preview_transaction(state, transaction, limits)
            .map(|(data, comparison)| (Self { data }, comparison))
            .map_err(JournalError::from)
    }

    pub(in crate::provider_journal) fn observe_compaction(&mut self, state: &State) {
        self.data.observe_compaction(state)
    }

    pub(in crate::provider_journal) fn replay_transaction(
        &mut self,
        state: &State,
        transaction: &JournalTransaction,
        challenges: Option<&SourceOriginalChallengeHistoryViewV5<'_>>,
        limits: JournalLimits,
        begin_sequence: u64,
        commit_sequence: u64,
        begin_offset: u64,
        durable_end: u64,
        committed_transactions: usize,
        journal_identity: (u64, u64),
    ) -> Result<bool, JournalError> {
        if !self.requires_history(state, transaction) {
            return Ok(false);
        }

        let Some(challenges) = challenges else {
            // The generic open remains inert. Only the fixed owner can close
            // this SAME physical parser with the separately held actual history.
            self.pending = true;
            return Ok(true);
        };
        challenges.validate_current()?;

        // Preflight the complete retained payload before any prospective map or
        // cut allocation. Adjacent cuts share their identical immutable map.
        let before_bytes = super::bounded_snapshot_bytes(state, limits)?;
        let after_bytes = prospective_payload_bytes(state, transaction, before_bytes)?;
        let previous_after = self.cuts.last().filter(|cut| cut.after_rows() == state);
        let retained_before_bytes = if previous_after.is_some() { 0 } else { before_bytes };
        let additional = after_bytes.checked_add(retained_before_bytes)
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<SourceOriginalPhysicalCutV5>()))
            .ok_or(JournalError::LimitExceeded("Source retained physical cuts"))?;
        if self.retained_bytes.checked_add(additional)
            .is_none_or(|bytes| bytes > limits.maximum_materialized_bytes)
        {
            return Err(JournalError::LimitExceeded("Source retained physical cuts"));
        }
        let prospective = aos_sandbox_ledger_replay::replay::root_original_inventory::materialize(
            state, transaction,
        );
        let added = transaction.records().len() == 5
            && transaction.records().iter().any(|record| {
                record.namespace() == RecordNamespace::GlobalCapacityReservation
                    && record.value().is_some_and(|value| value.get(8..10) == Some(&5_u16.to_be_bytes()))
                    && aos_sandbox_protocol::domain_ledger::capacity_family::family::CanonicalCapacityFamily::decode(
                        record.key(), record.value().unwrap_or_default(),
                    ).map_err(JournalError::from).is_ok_and(|family| matches!(family,
                        aos_sandbox_protocol::domain_ledger::capacity_family::family::CanonicalCapacityFamily::OriginalSource5(_)))
            });
        let mut admission = if added {
            let admission_payload = admission_payload_bound(state, transaction)?;
            let cut_bytes = super::bounded_snapshot_bytes(state, limits)?
                .checked_add(super::bounded_snapshot_bytes(&prospective, limits)?)
                .and_then(|bytes| bytes.checked_add(self.retained_bytes))
                .and_then(|bytes| bytes.checked_add(admission_payload))
                .ok_or(JournalError::LimitExceeded("Source retained original cuts"))?;
            if cut_bytes > limits.maximum_materialized_bytes {
                return Err(JournalError::LimitExceeded("Source retained original cuts"));
            }
            // Only the real five-row original Applying comparator can create an
            // origin. A later successor PUT does not satisfy that comparator.
            compare_source_original_admission_data_v5(
                SourceOriginalAdmissionInputV5 {
                    original_before: state,
                    original_applying: transaction,
                },
                limits,
            ).ok()
        } else {
            None
        };
        if let Some(admission) = admission.as_mut()
            && let Some(previous) = self.cuts.last()
        {
            admission.reuse_retained_before(&previous.after)?;
        }
        let admission_rows = admission.as_ref().map(SourceOriginalAdmissionDataV5::retained_cut_rows);
        if let Some(admission) = admission {
            self.retain_admission(admission, transaction, limits)?;
        }

        let (comparison, selected_challenges) = self.compare(state, Some(transaction), challenges, limits)?;
        let challenge_checkpoint = match selected_challenges.as_slice() {
            [] => None,
            [selected] => Some(challenges.retained_rows()?.iter().position(|checkpoint| {
                checkpoint.key() == selected.key && checkpoint.value() == selected.value
            }).ok_or(JournalError::ProtectedBoundary)?),
            _ => return Err(JournalError::ProtectedBoundary),
        };
        require_advisory_bounds(
            &comparison,
            limits,
            durable_end,
            committed_transactions,
            commit_sequence.checked_add(1).ok_or(JournalError::SequenceExhausted)?,
        )?;
        if let Some(edge) = comparison.owner_edge()
            && let Some(retirement) = edge.retirement()
        {
            let origin = self.origins.iter().find(|origin| {
                origin.admission_comparison().original().acquisition_id == edge.acquisition()
            }).ok_or(invalid("Source physical retirement has no original"))?;
            let width = retirement_width(origin, comparison.after())?;
            let previous = self.current_retirement_bytes.get(&edge.acquisition()).copied()
                .unwrap_or_default();
            let next = self.retained_bytes.checked_sub(previous)
                .and_then(|bytes| bytes.checked_add(width))
                .ok_or(JournalError::LimitExceeded("Source retained final carriers"))?;
            if next > limits.maximum_materialized_bytes {
                return Err(JournalError::LimitExceeded("Source retained final carriers"));
            }
            let origin = self.origins.iter_mut().find(|origin| {
                origin.admission_comparison().original().acquisition_id == edge.acquisition()
            }).ok_or(invalid("Source physical retirement has no original"))?;
            origin.retain_compared_retirement(retirement)?;
            self.current_retirement_bytes.insert(edge.acquisition(), width);
            self.retained_bytes = next;
        }

        let (before, after, new_payload) = match admission_rows {
            Some((before, after)) => (before, after, 0),
            None => {
                let (before, before_payload) = match self.cuts.last() {
                    Some(previous) if previous.after_rows() == state => (Arc::clone(&previous.after), 0),
                    _ => (Arc::new(state.clone()), before_bytes),
                };
                (before, Arc::new(prospective), before_payload.checked_add(after_bytes)
                    .ok_or(JournalError::LimitExceeded("Source retained physical cuts"))?)
            }
        };

        // Descriptor count/payload is bounded before retention. Ordinary cuts
        // before the first dependency are streamed and discarded by the parser.
        self.retained_bytes = self.retained_bytes.checked_add(new_payload)
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<SourceOriginalPhysicalCutV5>()))
            .ok_or(JournalError::LimitExceeded("Source retained physical cuts"))?;
        if self.retained_bytes > limits.maximum_materialized_bytes {
            return Err(JournalError::LimitExceeded("Source retained physical cuts"));
        }
        self.cuts.push(SourceOriginalPhysicalCutV5 {
            device: journal_identity.0,
            inode: journal_identity.1,
            transaction: *transaction.id(),
            digest: super::super::authority_preflight_digest(std::slice::from_ref(transaction)),
            begin_sequence,
            commit_sequence,
            begin_offset,
            durable_end,
            before,
            after,
            challenge_checkpoint,
        });
        self.pending = false;
        Ok(true)
    }

    fn retain_admission(
        &mut self,
        admission: SourceOriginalAdmissionDataV5,
        transaction: &JournalTransaction,
        limits: JournalLimits,
    ) -> Result<(), JournalError> {
        self.data.retain_admission(admission, transaction, limits).map_err(JournalError::from)
    }

    pub(super) fn compare<'challenge>(
        &self,
        state: &State,
        transaction: Option<&JournalTransaction>,
        challenges: &'challenge SourceOriginalChallengeHistoryViewV5<'_>,
        limits: JournalLimits,
    ) -> Result<(SourceCapacityUnionComparisonDataV5, Vec<OriginalSourceChallengeDataV5<'challenge>>), JournalError> {
        challenges.validate_current()?;
        self.compare_rows(
            state,
            transaction,
            challenges.retained_rows()?,
            limits,
        )
    }

    fn compare_rows<'challenge>(
        &self,
        state: &State,
        transaction: Option<&JournalTransaction>,
        challenges: &'challenge [SourceOriginalChallengeCheckpointV5],
        limits: JournalLimits,
    ) -> Result<(SourceCapacityUnionComparisonDataV5, Vec<OriginalSourceChallengeDataV5<'challenge>>), JournalError> {
        self.data.compare_rows(state, transaction, challenges, limits).map_err(JournalError::from)
    }

}

pub(in crate::provider_journal) fn require_advisory_bounds(
    comparison: &SourceCapacityUnionComparisonDataV5,
    limits: JournalLimits,
    journal_bytes: u64,
    transactions: usize,
    next_sequence: u64,
) -> Result<(), JournalError> {
    aos_sandbox_ledger_replay::replay::source_original::cache::require_advisory_bounds(
        comparison, limits, journal_bytes, transactions, next_sequence,
    ).map_err(JournalError::from)
}

pub(in crate::provider_journal) fn has_original_rows(state: &State) -> bool {
    aos_sandbox_ledger_replay::replay::source_original::cache::has_original_rows(state)
}

fn is_original_row(namespace: RecordNamespace, key: &[u8], value: &[u8]) -> bool {
    aos_sandbox_ledger_replay::replay::source_original::cache::is_original_row(namespace, key, value)
}

#[cfg(test)]
mod tests;
