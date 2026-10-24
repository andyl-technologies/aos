//! Interleaves the sole canonical cursor and actual resident index stages.
//!
//! This shared mechanical adapter adds no role constructor or semantic grant.
//! Upper role owners retain their own checks between these exact stages. Actual
//! cursor and index captures remain borrowed until their genuine owner decides
//! disposition; error projection never replaces their first concrete cause.

use std::collections::BTreeMap;

use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use aos_sandbox_protocol::domain_ledger::readonly::{
    self, IdempotencyDecisionV1, IdempotencyRecordDataErrorV1,
};

use crate::canonical_journal::{
    CanonicalCommitReadViewV1, CanonicalReplayCursorV1, CanonicalReplayExtentDataV1,
};

/// Classifies a cursor-owned native refusal or an original index-stage boundary.
#[derive(Debug, thiserror::Error)]
pub enum CanonicalIndexedReplayErrorV1 {
    /// Preserves the actual native stopping result; its capture keeps the cause.
    #[error(transparent)]
    Native(#[from] crate::canonical_journal::NativeJournalDataErrorV1),
    /// Refuses ordering, missing original or a retained index failure.
    #[error("indexed replay stage is closed")]
    Closed,
}

type Index = BTreeMap<Vec<u8>, IdempotencyDecisionV1>;

/// Retains the original comparison/application outcomes across later refusals.
pub struct CanonicalReplayIndexOriginalsV1 {
    comparison: Option<Result<(), IdempotencyRecordDataErrorV1>>,
    application: Option<Result<(), IdempotencyRecordDataErrorV1>>,
    entered: bool,
    complete: bool,
}

impl CanonicalReplayIndexOriginalsV1 {
    /// Constructs vacant comparison/application controls without allocation.
    pub const fn new() -> Self {
        Self { comparison: None, application: None, entered: false, complete: false }
    }

    /// Returns zero namespace metadata entries for these inline controls.
    ///
    /// Rust fields, Result carriers and B-tree nodes are byte representations;
    /// their sizeof/backing costs belong to MemoryBytes, not namespace counts.
    pub const fn receiving_metadata_cells_v1() -> u64 {
        0
    }

    /// Bounds actual-prefix index backing before the first parser allocation.
    ///
    /// # Errors
    /// Returns a closed marker on width or checked geometry overflow.
    pub fn dynamic_demand_v1(
        extent: CanonicalReplayExtentDataV1,
    ) -> Result<ResourceVector, CanonicalIndexedReplayErrorV1> {
        let invalid = || CanonicalIndexedReplayErrorV1::Closed;
        let bytes = usize::try_from(extent.native_bytes()).map_err(|_| invalid())?;
        let count = bytes / aos_sandbox_journal::framing::HEADER_BYTES;
        // This insert-only replay index has at most one node per reached key.
        // Each key needs a RECORD frame, so captured bytes/HEADER bounds its
        // cardinality without multiplying unrelated configured maxima. Shared
        // pinned node geometry includes alignment, slots, headers and edges;
        // three actual-prefix byte lanes cover key allocation and growth.
        let node_bytes = aos_sandbox_journal::geometry::conservative_btree_node_bytes_v1::<
            Vec<u8>, IdempotencyDecisionV1,
        >(count).ok_or_else(invalid)?;
        let memory = Some(node_bytes)
            .and_then(|value| value.checked_add(bytes.checked_mul(3)?))
            .and_then(|value| value.checked_add(std::mem::size_of::<CanonicalIndexedReplayV1<'_, '_>>().checked_mul(3)?))
            .ok_or_else(invalid)?;
        Ok(ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(memory).map_err(|_| invalid())?)
            // Each resident index decision corresponds to at least one actual
            // RECORD frame in this held prefix. Inserts do not delete entries,
            // so the prefix-derived count bounds namespace entry cardinality.
            // Node fields/edges and key allocation headers add no entries.
            .with(D::MetadataEntries, u64::try_from(count).map_err(|_| invalid())?))
    }

    /// Reports completed mechanical replay without a semantic or role grant.
    pub fn is_complete(&self) -> bool {
        self.entered && self.complete && self.failure().is_none()
    }

    /// Moves the same ordinary comparison/application cause after cursor disposal.
    ///
    /// Selected callers keep this original and borrow its failure instead.
    #[must_use]
    pub fn into_ordinary_error(self) -> Option<IdempotencyRecordDataErrorV1> {
        self.comparison.and_then(Result::err).or_else(|| self.application.and_then(Result::err))
    }

    /// Borrows the first retained index comparison or application failure.
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.comparison.as_ref().and_then(|result| result.as_ref().err())
            .map(|cause| cause as &(dyn std::error::Error + 'static))
            .or_else(|| self.application.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn std::error::Error + 'static)))
    }
}

/// Borrows one supplied canonical cursor and its actual resident index together.
///
/// Construction supplies mechanical DATA only. Genuine role owners privately
/// choose their original cursor, captured index and funding. This adapter cannot
/// enroll a Bank, confirm PID1, create RootR or emit a protected role loan.
pub struct CanonicalIndexedReplayV1<'file, 'original> {
    cursor: CanonicalReplayCursorV1<'file, 'original>,
    index: &'original mut Index,
    originals: &'original mut CanonicalReplayIndexOriginalsV1,
}

impl<'file, 'original> CanonicalIndexedReplayV1<'file, 'original> {
    /// Borrows supplied mechanical parts without cloning or admitting a role.
    pub fn from_supplied_data_v1(
        cursor: CanonicalReplayCursorV1<'file, 'original>,
        index: &'original mut Index,
        originals: &'original mut CanonicalReplayIndexOriginalsV1,
    ) -> Self {
        originals.entered = true;
        Self { cursor, index, originals }
    }

    fn require_active(&self) -> Result<(), CanonicalIndexedReplayErrorV1> {
        if self.originals.complete || self.originals.failure().is_some() {
            return Err(CanonicalIndexedReplayErrorV1::Closed);
        }
        Ok(())
    }

    /// Advances the sole parser to its next actual canonical COMMIT.
    ///
    /// # Errors
    /// Preserves its resident native/parser cause and refuses incomplete steps.
    pub fn advance_once(&mut self) -> Result<bool, CanonicalIndexedReplayErrorV1> {
        self.require_active()?;
        let reached = self.cursor.advance_once()?;
        if !reached {
            self.originals.complete = true;
        }
        Ok(reached)
    }

    /// Borrows the actual transaction and preceding map as comparison DATA.
    pub fn current_commit(&self) -> Option<CanonicalCommitReadViewV1<'_>> {
        self.require_active().ok()?;
        self.cursor.current_commit()
    }

    /// Borrows the same completed structural prefix for final upper semantics.
    #[must_use]
    pub fn completed_prefix(&self) -> Option<crate::canonical_journal::CanonicalReplayPrefixReadViewV1<'_>> {
        if !self.originals.is_complete() {
            return None;
        }
        self.cursor.completed_prefix()
    }

    /// Runs the same native compaction check after earlier upper role checks.
    ///
    /// # Errors
    /// Preserves actual compaction or staged-order refusal.
    pub fn validate_compaction_once(&mut self) -> Result<(), CanonicalIndexedReplayErrorV1> {
        self.require_active()?;
        Ok(self.cursor.validate_compaction_once()?)
    }

    /// Registers the actual transaction before its original index comparison.
    ///
    /// # Errors
    /// Preserves duplicate/native order and resident index conflict causes.
    pub fn register_and_compare_index_once(&mut self) -> Result<(), CanonicalIndexedReplayErrorV1> {
        self.require_active()?;
        self.cursor.register_transaction_once()?;
        let current = self.cursor.current_commit().ok_or(CanonicalIndexedReplayErrorV1::Closed)?;
        self.originals.comparison = Some(readonly::validate_idempotency_changes(
            self.index, current.transaction().records(),
        ));
        if !matches!(self.originals.comparison, Some(Ok(()))) {
            return Err(CanonicalIndexedReplayErrorV1::Closed);
        }
        Ok(())
    }

    /// Prepares native materialization after the original index comparison.
    ///
    /// # Errors
    /// Refuses a missing/failed comparison or native materialization error.
    pub fn prepare_change_once(&mut self) -> Result<(), CanonicalIndexedReplayErrorV1> {
        self.require_active()?;
        if !matches!(self.originals.comparison, Some(Ok(()))) {
            return Err(CanonicalIndexedReplayErrorV1::Closed);
        }
        Ok(self.cursor.prepare_change_once()?)
    }

    /// Applies each actual native record before its same resident index update.
    ///
    /// # Errors
    /// Retains the actual typed index Result before projecting a boundary error.
    pub fn apply_next_record_once(&mut self) -> Result<bool, CanonicalIndexedReplayErrorV1> {
        self.require_active()?;
        let applied = self.cursor.apply_next_record_once()?;
        if applied {
            let record = self.cursor.last_applied_record().ok_or(CanonicalIndexedReplayErrorV1::Closed)?;
            self.originals.application = Some(readonly::apply_idempotency_record(self.index, record));
            if !matches!(self.originals.application, Some(Ok(()))) {
                return Err(CanonicalIndexedReplayErrorV1::Closed);
            }
        }
        Ok(applied)
    }

    /// Completes accounting while retaining the actual COMMIT for upper checks.
    ///
    /// # Errors
    /// Preserves native unfinished-record, count and sequence refusals.
    pub fn finish_commit_accounting_once(&mut self) -> Result<(), CanonicalIndexedReplayErrorV1> {
        self.require_active()?;
        Ok(self.cursor.finish_commit_accounting_once()?)
    }

    /// Disposes the accounted COMMIT after the actual final upper checks.
    ///
    /// # Errors
    /// Preserves native unfinished-record, count and sequence refusals.
    pub fn finish_commit_once(&mut self) -> Result<(), CanonicalIndexedReplayErrorV1> {
        self.require_active()?;
        self.cursor.dispose_completed_commit_once()?;
        // These completed comparison markers carry no owned allocation. Their
        // disposal remains at the old completed-transaction boundary.
        self.originals.comparison = None;
        self.originals.application = None;
        Ok(())
    }

    /// Borrows the earliest original parser or reached index cause.
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.cursor.failure().or_else(|| self.originals.failure())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use aos_sandbox_model::{OperationId, RecordNamespace};
    use aos_sandbox_protocol::domain_ledger::transaction::{
        self as data, JournalLimits, JournalRecord, JournalTransaction,
    };
    use crate::canonical_journal::CanonicalReplayOriginalV1;

    fn index_transaction() -> JournalTransaction {
        let mut decision = vec![3; 32];
        decision.extend_from_slice(&[4; 16]);
        JournalTransaction::new([7; 16], vec![JournalRecord::put(
            RecordNamespace::Idempotency, vec![1, 2], decision,
        )]).unwrap()
    }

    fn write_transaction(file: &mut std::fs::File, transaction: &JournalTransaction) {
        for frame in data::encode_transaction(transaction, 1).unwrap() {
            file.write_all(&frame).unwrap();
        }
    }

    #[test]
    fn real_index_conflict_retains_first_cause_transaction_and_prior_index() {
        let mut file = tempfile::tempfile().unwrap();
        write_transaction(&mut file, &index_transaction());
        let length = file.metadata().unwrap().len();
        let mut native = CanonicalReplayOriginalV1::new();
        let cursor = native.begin_semantic_cursor_once(&file, JournalLimits::default(), length).unwrap();
        let mut index = BTreeMap::from([(vec![1, 2], IdempotencyDecisionV1 {
            request_digest: [9; 32], operation_id: OperationId::from_bytes([4; 16]),
        })]);
        let index_pointer = index.keys().next().unwrap().as_ptr();
        let mut original = CanonicalReplayIndexOriginalsV1::new();
        let mut replay = CanonicalIndexedReplayV1::from_supplied_data_v1(cursor, &mut index, &mut original);

        assert!(replay.advance_once().unwrap());
        let packet = replay.current_commit().unwrap().transaction().records()[0].key().as_ptr();
        replay.validate_compaction_once().unwrap();
        assert!(matches!(replay.register_and_compare_index_once(), Err(CanonicalIndexedReplayErrorV1::Closed)));
        let cause = replay.failure().unwrap() as *const dyn std::error::Error;
        assert!(replay.prepare_change_once().is_err());
        assert!(replay.advance_once().is_err());

        assert!(std::ptr::eq(cause, replay.failure().unwrap() as *const dyn std::error::Error));
        // The native cursor still owns the failed COMMIT even though the index
        // adapter refuses exposing it after the comparison failure.
        drop(replay);
        assert!(matches!(original.comparison, Some(Err(IdempotencyRecordDataErrorV1::Conflict))));
        assert_eq!(index.keys().next().unwrap().as_ptr(), index_pointer);
        let work = native.work.as_ref().unwrap();
        assert!(work.state.is_empty());
        assert_eq!(work.transaction.as_ref().unwrap().records()[0].key().as_ptr(), packet);
    }

    #[test]
    fn actual_record_then_index_and_accounting_preserve_final_semantic_window() {
        let mut file = tempfile::tempfile().unwrap();
        write_transaction(&mut file, &index_transaction());
        let length = file.metadata().unwrap().len();
        let mut native = CanonicalReplayOriginalV1::new();
        let cursor = native.begin_semantic_cursor_once(&file, JournalLimits::default(), length).unwrap();
        let mut index = BTreeMap::new();
        let mut original = CanonicalReplayIndexOriginalsV1::new();
        let mut replay = CanonicalIndexedReplayV1::from_supplied_data_v1(cursor, &mut index, &mut original);

        assert!(replay.advance_once().unwrap());
        replay.validate_compaction_once().unwrap();
        replay.register_and_compare_index_once().unwrap();
        replay.prepare_change_once().unwrap();
        let packet = replay.current_commit().unwrap().transaction().records()[0].key().as_ptr();
        assert!(replay.apply_next_record_once().unwrap());
        assert!(replay.index.contains_key([1, 2].as_slice()));
        assert!(replay.current_commit().unwrap().prior_state().contains_key(&(
            RecordNamespace::Idempotency, vec![1, 2],
        )));
        assert!(!replay.apply_next_record_once().unwrap());
        replay.finish_commit_accounting_once().unwrap();

        assert_eq!(replay.current_commit().unwrap().transaction().records()[0].key().as_ptr(), packet);
        replay.finish_commit_once().unwrap();
        assert!(replay.current_commit().is_none());
        assert!(!replay.advance_once().unwrap());
        assert!(replay.completed_prefix().is_some());
        drop(replay);
        assert!(original.is_complete());
        assert!(original.failure().is_none());
        assert_eq!(index.get([1, 2].as_slice()).unwrap().request_digest, [3; 32]);
    }
}
