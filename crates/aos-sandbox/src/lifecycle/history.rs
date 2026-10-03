//! Bounded hostile replay for lifecycle operation snapshots.

use std::collections::{BTreeMap, BTreeSet};

use aos_sandbox_core::{ObjectDigest, OperationId};
use sha2::{Digest as _, Sha256};

use super::format::record_digest;
use super::{
    LifecycleCancelIdempotencyIndexV1, LifecycleCancelOutcomeV1, LifecycleCancelRequestV1,
    LifecycleIdempotencyIndexV1, LifecycleModelError, LifecycleOperationV1,
    LifecycleRecordDigestV1, decode_operation_record_v1, encode_operation_record_v1,
};

/// Maximum records accepted by one replay.
pub const MAXIMUM_LIFECYCLE_HISTORY_RECORDS: usize = 262_144;
/// Maximum aggregate encoded bytes accepted by one replay.
pub const MAXIMUM_LIFECYCLE_HISTORY_BYTES: usize = 512 * 1024 * 1024;

/// Stores a trusted replay floor and its fully validated materialized state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct LifecycleHistoryCheckpointV1 {
    pub(super) floor_semantic_sequence: Option<u64>,
    pub(super) digest: ObjectDigest,
    pub(super) history: LifecycleHistoryV1,
}

/// Materializes the latest valid snapshot for each operation.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LifecycleHistoryV1 {
    pub(super) operations: BTreeMap<OperationId, LifecycleOperationV1>,
    pub(super) record_digests: BTreeMap<OperationId, LifecycleRecordDigestV1>,
    pub(super) latest_semantic_commit_sequence: Option<u64>,
    pub(super) idempotency: LifecycleIdempotencyIndexV1,
    pub(super) cancellations: LifecycleCancelIdempotencyIndexV1,
    pub(super) retained_records: usize,
    pub(super) retained_bytes: usize,
}

impl LifecycleHistoryCheckpointV1 {
    /// Returns the complete materialized checkpoint commitment.
    #[must_use]
    pub const fn digest(&self) -> ObjectDigest {
        self.digest
    }

    /// Returns the greatest retained semantic-commit sequence.
    #[must_use]
    pub const fn floor_semantic_sequence(&self) -> Option<u64> {
        self.floor_semantic_sequence
    }
}

impl LifecycleHistoryV1 {
    /// Replays exact records under fixed count and aggregate-byte ceilings.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleReplayError`] for malformed records, a broken chain,
    /// changed immutable intent, regressed progress, or exhausted bounds.
    pub(super) fn replay<'a>(
        records: impl IntoIterator<Item = &'a [u8]>,
    ) -> Result<Self, LifecycleReplayError> {
        let mut history = Self::default();
        for encoded in records {
            let operation = decode_operation_record_v1(encoded)?;
            history.apply(operation, record_digest(encoded)?)?;
        }
        Ok(history)
    }

    /// Replays a bounded suffix from a previously validated compaction floor.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleReplayError`] under the same conditions as
    /// [`Self::replay`], including a suffix that conflicts with the checkpoint.
    pub(super) fn replay_after<'a>(
        checkpoint: &LifecycleHistoryCheckpointV1,
        records: impl IntoIterator<Item = &'a [u8]>,
    ) -> Result<Self, LifecycleReplayError> {
        let mut history = checkpoint.history.clone();
        if history.latest_semantic_commit_sequence != checkpoint.floor_semantic_sequence
            || history.complete_digest()? != checkpoint.digest
        {
            return Err(LifecycleReplayError::Conflict);
        }
        for encoded in records {
            let operation = decode_operation_record_v1(encoded)?;
            history.apply(operation, record_digest(encoded)?)?;
        }
        Ok(history)
    }

    /// Captures a trusted compaction floor from this replay-validated state.
    pub(super) fn checkpoint(&self) -> Result<LifecycleHistoryCheckpointV1, LifecycleReplayError> {
        let mut history = self.clone();
        history.compact_materialization()?;
        Ok(LifecycleHistoryCheckpointV1 {
            floor_semantic_sequence: history.latest_semantic_commit_sequence,
            digest: history.complete_digest()?,
            history,
        })
    }

    pub(super) fn compact_materialization(&mut self) -> Result<(), LifecycleReplayError> {
        if self.operations.len() > MAXIMUM_LIFECYCLE_HISTORY_RECORDS {
            return Err(LifecycleReplayError::Capacity);
        }
        self.retained_records = self.operations.len();
        self.retained_bytes = self
            .operations
            .values()
            .try_fold(0_usize, |total, operation| {
                total
                    .checked_add(encode_operation_record_v1(operation)?.len())
                    .filter(|bytes| *bytes <= MAXIMUM_LIFECYCLE_HISTORY_BYTES)
                    .ok_or(LifecycleReplayError::Capacity)
            })?;
        Ok(())
    }

    pub(super) fn from_compacted_operations<'a>(
        operations: impl IntoIterator<Item = &'a LifecycleOperationV1>,
        cancellations: impl IntoIterator<Item = &'a super::LifecycleCancellationRecordV1>,
    ) -> Result<Self, LifecycleReplayError> {
        let mut history = Self::default();
        let mut semantic_sequences = BTreeSet::new();
        for operation in operations {
            let encoded = encode_operation_record_v1(operation)?;
            let digest = record_digest(&encoded)?;
            if history.operations.contains_key(&operation.operation_id()) {
                return Err(LifecycleReplayError::Conflict);
            }
            history
                .idempotency
                .observe(operation)
                .map_err(|()| LifecycleReplayError::Conflict)?;
            if let Some(commit) = operation.semantic_commit() {
                if !semantic_sequences.insert(commit.sequence()) {
                    return Err(LifecycleReplayError::Conflict);
                }
                history.latest_semantic_commit_sequence = Some(
                    history
                        .latest_semantic_commit_sequence
                        .map_or(commit.sequence(), |latest| latest.max(commit.sequence())),
                );
            }
            history
                .operations
                .insert(operation.operation_id(), operation.clone());
            history
                .record_digests
                .insert(operation.operation_id(), digest);
        }
        for cancellation in cancellations {
            history.cancellations.apply_record(cancellation)?;
        }
        history.compact_materialization()?;
        Ok(history)
    }

    /// Returns the latest validated operation snapshot.
    #[must_use]
    pub fn operation(&self, operation_id: OperationId) -> Option<&LifecycleOperationV1> {
        self.operations.get(&operation_id)
    }

    /// Returns one exact current operation and its canonical record commitment.
    #[must_use]
    pub fn operation_record(
        &self,
        operation_id: OperationId,
    ) -> Option<(&LifecycleOperationV1, LifecycleRecordDigestV1)> {
        self.operations
            .get(&operation_id)
            .zip(self.record_digests.get(&operation_id).copied())
    }

    /// Iterates over latest operation snapshots in stable identity order.
    pub fn operations(&self) -> impl Iterator<Item = &LifecycleOperationV1> {
        self.operations.values()
    }

    pub(super) fn apply_materialized(
        &mut self,
        operation: LifecycleOperationV1,
        record_digest: LifecycleRecordDigestV1,
    ) -> Result<(), LifecycleReplayError> {
        self.apply(operation, record_digest)
    }

    pub(super) fn apply_cancellation_record(
        &mut self,
        record: &super::LifecycleCancellationRecordV1,
    ) -> Result<(), LifecycleReplayError> {
        let operation = self
            .operation_record(record.operation().operation_id())
            .ok_or(LifecycleReplayError::Conflict)?;
        if operation.0 != record.operation() {
            return Err(LifecycleReplayError::Conflict);
        }
        self.cancellations.apply_record(record)?;
        Ok(())
    }

    /// Borrows the replay-validated durable idempotency index.
    #[must_use]
    pub const fn idempotency(&self) -> &LifecycleIdempotencyIndexV1 {
        &self.idempotency
    }

    /// Borrows the durable cancellation-idempotency index.
    #[must_use]
    pub const fn cancellations(&self) -> &LifecycleCancelIdempotencyIndexV1 {
        &self.cancellations
    }

    pub(super) fn complete_digest(&self) -> Result<ObjectDigest, LifecycleModelError> {
        let mut hasher = Sha256::new()
            .chain_update(b"aos.sandbox.lifecycle.history-checkpoint.v1\0")
            .chain_update((self.retained_records as u64).to_be_bytes())
            .chain_update((self.retained_bytes as u64).to_be_bytes())
            .chain_update(
                self.latest_semantic_commit_sequence
                    .unwrap_or(0)
                    .to_be_bytes(),
            )
            .chain_update(self.idempotency.complete_digest().as_bytes())
            .chain_update(self.cancellations.complete_digest()?.as_bytes());
        for (operation, digest) in &self.record_digests {
            hasher = hasher
                .chain_update(operation.as_bytes())
                .chain_update(digest.digest().as_bytes());
        }
        Ok(ObjectDigest::from_bytes(hasher.finalize().into()))
    }

    /// Resolves a cancel race and atomically applies its exact successor.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleReplayError`] if the indexed successor cannot be
    /// encoded or applied against the same replay-validated record.
    pub(super) fn resolve_cancel(
        &mut self,
        request: LifecycleCancelRequestV1,
    ) -> Result<LifecycleCancelOutcomeV1, LifecycleReplayError> {
        if let Some(outcome) = self.cancellations.lookup(request) {
            return Ok(outcome);
        }
        let operation = self
            .operations
            .get(&request.operation_id())
            .ok_or(LifecycleReplayError::Conflict)?;
        let digest = self
            .record_digests
            .get(&request.operation_id())
            .copied()
            .ok_or(LifecycleReplayError::Conflict)?;
        let mut cancellations = self.cancellations.clone();
        let outcome = cancellations.resolve(request, operation, digest);
        let mut next = self.clone();
        if let LifecycleCancelOutcomeV1::CanceledBeforeCommit(successor) = &outcome {
            let encoded = encode_operation_record_v1(successor)?;
            next.apply(successor.clone(), record_digest(&encoded)?)?;
        }
        next.cancellations = cancellations;
        *self = next;
        Ok(outcome)
    }

    fn apply(
        &mut self,
        operation: LifecycleOperationV1,
        record_digest: LifecycleRecordDigestV1,
    ) -> Result<(), LifecycleReplayError> {
        let encoded_length = encode_operation_record_v1(&operation)?.len();
        let retained_records = self
            .retained_records
            .checked_add(1)
            .filter(|count| *count <= MAXIMUM_LIFECYCLE_HISTORY_RECORDS)
            .ok_or(LifecycleReplayError::Capacity)?;
        let retained_bytes = self
            .retained_bytes
            .checked_add(encoded_length)
            .filter(|bytes| *bytes <= MAXIMUM_LIFECYCLE_HISTORY_BYTES)
            .ok_or(LifecycleReplayError::Capacity)?;
        // Validate duplicate admission before any progress or recovery evidence
        // from this record can be considered.
        let mut idempotency = self.idempotency.clone();
        idempotency
            .observe(&operation)
            .map_err(|()| LifecycleReplayError::Conflict)?;
        let operation_id = operation.operation_id();
        if !self.operations.contains_key(&operation_id)
            && self.operations.len() >= MAXIMUM_LIFECYCLE_HISTORY_RECORDS
        {
            return Err(LifecycleReplayError::Capacity);
        }
        let introduces_semantic_commit = operation.semantic_commit().is_some()
            && self
                .operations
                .get(&operation_id)
                .is_none_or(|previous| previous.semantic_commit().is_none());
        if introduces_semantic_commit
            && self.latest_semantic_commit_sequence.is_some_and(|latest| {
                operation
                    .semantic_commit()
                    .is_none_or(|commit| commit.sequence() <= latest)
            })
        {
            return Err(LifecycleReplayError::Conflict);
        }
        match (
            self.operations.get(&operation_id),
            self.record_digests.get(&operation_id),
        ) {
            (None, None) if operation.predecessor_digest().is_none() => {}
            (Some(previous), Some(previous_digest))
                if operation.predecessor_digest() == Some(*previous_digest) =>
            {
                let mut steps = Vec::new();
                steps
                    .try_reserve_exact(operation.steps().len())
                    .map_err(|_| LifecycleReplayError::Model(LifecycleModelError::Allocation))?;
                steps.extend_from_slice(operation.steps());
                let reconstructed = previous.successor(
                    *previous_digest,
                    operation.phase(),
                    operation.forward_progress(),
                    operation.compensation_progress(),
                    steps,
                    operation.method_semantic_commit().cloned(),
                    operation.failure(),
                    operation.retry(),
                    operation.terminal_result(),
                    operation.finished_at(),
                )?;
                if reconstructed != operation {
                    return Err(LifecycleReplayError::Conflict);
                }
            }
            _ => return Err(LifecycleReplayError::Conflict),
        }
        if introduces_semantic_commit {
            self.latest_semantic_commit_sequence =
                operation.semantic_commit().map(|c| c.sequence());
        }
        self.operations.insert(operation_id, operation);
        self.record_digests.insert(operation_id, record_digest);
        self.idempotency = idempotency;
        self.retained_records = retained_records;
        self.retained_bytes = retained_bytes;
        Ok(())
    }
}

/// Reports a lifecycle replay failure.
#[derive(Debug, thiserror::Error)]
pub enum LifecycleReplayError {
    /// Replay exceeds its fixed count or byte ceiling.
    #[error("lifecycle history exceeds fixed replay capacity")]
    Capacity,
    /// A successor conflicts with the durable predecessor.
    #[error("lifecycle history contains a conflicting successor")]
    Conflict,
    /// A lifecycle record is malformed or violates monotone state.
    #[error(transparent)]
    Model(#[from] LifecycleModelError),
}
