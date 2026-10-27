//! Binds the sole semantic replay recipe to Source's actual challenge owner.
//!
//! Canonical Source/Root/capacity/Delete DATA predicates stay in LedgerReplay.
//! These private type bindings retain Source's real history witness identity;
//! no callback, supplied model or DATA result can create a native lender.

use std::collections::BTreeMap;

use aos_sandbox_broker::canonical_journal::coordinator::indexed_replay::CanonicalIndexedReplayErrorV1;
use aos_sandbox_journal::{protected_storage::FileIdentity, replay::NativeReplayCoordinates};
use aos_sandbox_ledger_replay::genesis::SourceGenesisReceiptDataErrorV1;
use aos_sandbox_ledger_replay::replay::{
    RootReplayOwnerEdgeV1 as RootOwnerEdge, root_local_recovery, root_original_inventory,
    root_original_native,
};
use aos_sandbox_protocol::domain_ledger::DomainLedgerDataError;

use super::original as source_original_native;
use super::validate_transaction;
use super::{JournalError, JournalLimits, JournalRecord, JournalTransaction, RecordNamespace};

mod source_tree_successor {
    use super::*;
    use aos_sandbox_ledger_replay::replay::source_tree_successor as data;

    pub(super) use data::State;
    pub(super) type SourceReplayFamilyOriginalsV1 = data::SourceReplayFamilyOriginalsV1<
        JournalError,
        DomainLedgerDataError,
        SourceGenesisReceiptDataErrorV1,
    >;
    pub(super) type SourceReplayTransactionOriginalsV1 = data::SourceReplayTransactionOriginalsV1<
        JournalError,
        DomainLedgerDataError,
        SourceGenesisReceiptDataErrorV1,
    >;

    pub(super) fn validate_replayed_transaction(
        state: &State,
        transaction: &JournalTransaction,
        limits: JournalLimits,
    ) -> Result<bool, JournalError> {
        data::validate_replayed_transaction::<
            JournalError,
            DomainLedgerDataError,
            SourceGenesisReceiptDataErrorV1,
        >(state, transaction, limits)
    }

    pub(super) fn validate_replayed_state(
        state: &State,
        compacted: bool,
    ) -> Result<(), JournalError> {
        data::validate_replayed_state::<
            JournalError,
            DomainLedgerDataError,
            SourceGenesisReceiptDataErrorV1,
        >(state, compacted)
    }

    pub(super) fn validate_replayed_state_with_originals(
        state: &State,
        compacted: bool,
        original: Option<&mut SourceReplayFamilyOriginalsV1>,
    ) -> Result<(), JournalError> {
        data::validate_replayed_state_with_originals::<
            JournalError,
            DomainLedgerDataError,
            SourceGenesisReceiptDataErrorV1,
        >(state, compacted, original)
    }

    pub(super) fn require_sequence_headroom(
        state: &State,
        sequence: u64,
    ) -> Result<(), JournalError> {
        data::require_sequence_headroom(state, sequence)
    }
}

use super::delete_batch;

fn validate_reserved_capacity(
    state: &source_tree_successor::State,
    materialized_bytes: usize,
    records: &[JournalRecord],
    reservation: Option<[u8; 32]>,
    journal_bytes: u64,
    transactions: usize,
    limits: JournalLimits,
    _edge: Option<RootOwnerEdge>,
) -> Result<(), JournalError> {
    use aos_sandbox_broker::domain_transaction_custody::pressure::{
        CapacityDeletionSelectorDataV1, validate_reserved_capacity_data_v1,
    };

    // The shared replay recipe calls this after materialization with no owner
    // edge. Its unchanged empty-change capacity comparison grants no append
    // exception; the actual Source append keeps its own private selector.
    let deletion = CapacityDeletionSelectorDataV1::Reservation(reservation);
    validate_reserved_capacity_data_v1(
        state,
        materialized_bytes,
        records,
        deletion,
        journal_bytes,
        transactions,
        limits,
    )
    .map_err(JournalError::from)
}

fn source_native_family_fixed_footprint_v1() -> Option<(usize, usize)> {
    let (family, _) = source_tree_successor::SourceReplayFamilyOriginalsV1::boxed_footprint_v1()?;
    let (transaction, _) =
        source_tree_successor::SourceReplayTransactionOriginalsV1::boxed_footprint_v1()?;
    Some((family.checked_add(transaction)?, 0))
}

fn is_q04_lower_history_record_v1(record: &JournalRecord) -> bool {
    aos_sandbox_ledger_replay::semantic_recipe::is_q04_lower_history_record_data_v1(record)
}

mod semantic {
    use super::*;

    aos_sandbox_ledger_replay::define_semantic_replay_data_recipe_v1!();

    mod driver {
        use super::*;

        aos_sandbox_ledger_replay::define_semantic_replay_data_recipe_v1!(retained);
    }

    pub(in crate::provider_journal) use driver::SelectedSemanticRemainderDataV1;
    pub(super) use driver::{SelectedReplayNativeV1, SelectedSemanticReplayOriginalV1};
}

pub(super) use semantic::SelectedSemanticRemainderDataV1 as SourceSemanticRemainderDataV1;

/// Keeps the sole semantic driver beside Source's genuine indexed cursor.
pub(super) struct SourceSemanticReplayOriginalV1 {
    original: semantic::SelectedSemanticReplayOriginalV1<JournalError>,
}

impl SourceSemanticReplayOriginalV1 {
    pub(super) fn new() -> Self {
        Self {
            original: semantic::SelectedSemanticReplayOriginalV1::new(),
        }
    }

    /// Covers the actual semantic controls and its two short native borrowers.
    pub(super) fn receiving_construction_bytes_data_v1() -> Option<usize> {
        semantic::SelectedSemanticReplayOriginalV1::<JournalError>::receiving_construction_bytes_v1(
        )?
        .checked_add(std::mem::size_of::<SourceReplayNativeV1<'_, '_, '_>>().checked_mul(2)?)
    }

    pub(super) fn observe_ordinary_once(
        &mut self,
        cursor: &mut aos_sandbox_broker::canonical_journal::coordinator::indexed_replay::CanonicalIndexedReplayV1<'_, '_>,
        identity: FileIdentity,
        limits: JournalLimits,
        challenges: Option<&source_original_native::SourceOriginalChallengeHistoryViewV5<'_>>,
    ) -> Result<(), ()> {
        self.original.observe_ordinary_once(
            &mut SourceReplayNativeV1 {
                cursor,
                release: None,
            },
            identity,
            limits,
            challenges,
        )
    }

    pub(super) fn observe_release_once(
        &mut self,
        cursor: &mut aos_sandbox_broker::canonical_journal::coordinator::indexed_replay::CanonicalIndexedReplayV1<'_, '_>,
        identity: FileIdentity,
        limits: JournalLimits,
        challenges: &source_original_native::SourceOriginalChallengeHistoryViewV5<'_>,
        release: &mut SourceReleaseHistoryV1,
    ) -> Result<(), ()> {
        self.original.observe_ordinary_once(
            &mut SourceReplayNativeV1 {
                cursor,
                release: Some(release),
            },
            identity,
            limits,
            Some(challenges),
        )
    }

    pub(super) fn take_remainder_once(&mut self) -> Option<SourceSemanticRemainderDataV1> {
        self.original.take_remainder_once()
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.original.failure()
    }

    pub(super) fn dispose_ordinary_prospective_v1(&mut self) {
        self.original.dispose_ordinary_prospective_v1();
    }

    pub(super) fn into_ordinary_errors(self) -> (Option<JournalError>, Option<JournalError>) {
        self.original.into_ordinary_errors()
    }
}

// A closed adapter to the same canonical commit cursor, not another parser,
// byte loop, historical observer or Source-authority interface.
struct SourceReplayNativeV1<'turn, 'file, 'original> {
    cursor: &'turn mut aos_sandbox_broker::canonical_journal::coordinator::indexed_replay::CanonicalIndexedReplayV1<'file, 'original>,
    release: Option<&'turn mut SourceReleaseHistoryV1>,
}

impl semantic::SelectedReplayNativeV1 for SourceReplayNativeV1<'_, '_, '_> {
    type Error = JournalError;

    fn advance_once(&mut self) -> Result<bool, Self::Error> {
        self.cursor.advance_once().map_err(native_error)
    }

    fn observe_history_commit_once(&mut self) -> Result<(), Self::Error> {
        if let Some(release) = &mut self.release {
            let commit = self
                .cursor
                .current_commit()
                .ok_or(JournalError::ProtectedBoundary)?;
            release.observe(commit)?;
        }
        Ok(())
    }

    fn current_commit(
        &self,
    ) -> Option<aos_sandbox_broker::canonical_journal::CanonicalCommitReadViewV1<'_>> {
        self.cursor.current_commit()
    }

    fn validate_compaction_once(&mut self) -> Result<(), Self::Error> {
        self.cursor.validate_compaction_once().map_err(native_error)
    }

    fn register_and_compare_index_once(&mut self) -> Result<(), Self::Error> {
        self.cursor
            .register_and_compare_index_once()
            .map_err(native_error)
    }

    fn prepare_change_once(&mut self) -> Result<(), Self::Error> {
        self.cursor.prepare_change_once().map_err(native_error)
    }

    fn apply_next_record_once(&mut self) -> Result<bool, Self::Error> {
        self.cursor.apply_next_record_once().map_err(native_error)
    }

    fn finish_commit_accounting_once(&mut self) -> Result<(), Self::Error> {
        self.cursor
            .finish_commit_accounting_once()
            .map_err(native_error)
    }

    fn finish_commit_once(&mut self) -> Result<(), Self::Error> {
        self.cursor.finish_commit_once().map_err(native_error)
    }

    fn completed_prefix(
        &self,
    ) -> Option<aos_sandbox_broker::canonical_journal::CanonicalReplayPrefixReadViewV1<'_>> {
        self.cursor.completed_prefix()
    }

    fn finish_semantic_window_once(&mut self) -> Result<(), Self::Error> {
        self.cursor
            .completed_prefix()
            .ok_or(JournalError::ProtectedBoundary)?;
        Ok(())
    }
}

/// Retains Source Release's existing finite actual-COMMIT comparison audit.
pub(super) struct SourceReleaseHistoryV1 {
    remaining: usize,
    next_sequence: Option<u64>,
    durable_end: u64,
    head: Option<[u8; 32]>,
}

impl SourceReleaseHistoryV1 {
    pub(super) fn new(actual_transactions: usize) -> Self {
        Self {
            remaining: actual_transactions,
            next_sequence: None,
            durable_end: 0,
            head: None,
        }
    }

    fn observe(
        &mut self,
        commit: aos_sandbox_broker::canonical_journal::CanonicalCommitReadViewV1<'_>,
    ) -> Result<(), JournalError> {
        // The holder supplies the count. This hook runs BEFORE Source cache
        // retention at the same existing semantic COMMIT frontier.
        if self.remaining == 0 {
            return Err(JournalError::LimitExceeded(
                "Source original Release native transactions",
            ));
        }
        let (begin_sequence, begin_offset) = commit.begin_position();
        if self.next_sequence.is_none() {
            self.next_sequence = Some(begin_sequence);
            self.durable_end = begin_offset;
        }
        let commit_sequence = commit.commit_sequence();
        let end_offset = commit.coordinates().offset;
        let next = commit_sequence
            .checked_add(1)
            .ok_or(JournalError::SequenceExhausted)?;
        let frames = u64::try_from(commit.transaction().records().len())
            .map_err(|_| JournalError::LimitExceeded("original Release native frames"))?
            .checked_add(2)
            .ok_or(JournalError::SequenceExhausted)?;
        if Some(begin_sequence) != self.next_sequence
            || next.checked_sub(begin_sequence) != Some(frames)
            || begin_offset != self.durable_end
            || end_offset.checked_sub(begin_offset)
                != Some(super::encoded_transaction_append_bytes(
                    commit.transaction(),
                )?)
        {
            return Err(JournalError::ProtectedBoundary);
        }
        let head = commit.commit_payload()[4..]
            .try_into()
            .map_err(|_| JournalError::ProtectedBoundary)?;
        self.next_sequence = Some(next);
        self.durable_end = end_offset;
        self.head = Some(head);
        self.remaining -= 1;
        Ok(())
    }

    pub(super) fn require_completed(&self, next: u64, end: u64) -> Result<(), JournalError> {
        if self.remaining != 0
            || self.head.is_none_or(|head| head == [0; 32])
            || next == 0
            || next == u64::MAX
            || self.next_sequence != Some(next)
            || self.durable_end != end
        {
            return Err(JournalError::StaleAuthoritySnapshot);
        }
        Ok(())
    }
}

fn native_error(cause: CanonicalIndexedReplayErrorV1) -> JournalError {
    match cause {
        CanonicalIndexedReplayErrorV1::Native(cause) => {
            JournalError::from_ordinary_native_v1(cause)
        }
        CanonicalIndexedReplayErrorV1::Closed => JournalError::ProtectedBoundary,
    }
}
