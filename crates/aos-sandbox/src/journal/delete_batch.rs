//! Selected Delete native CAS and same-parser COMMIT comparison DATA.
//!
//! The adapter borrows the native map and canonical batch codec. It does not
//! authenticate the supplied graph, Source reference, independent Root floor,
//! physical retirement or a caller's permission to delete anything.

use super::*;
use crate::lifecycle::delete_batch::{self as codec, DeleteBatchViewV1};

pub(super) fn has_dependencies(state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>) -> bool {
    state.keys().any(|(namespace, key)| {
        *namespace == RecordNamespace::DesiredState && codec::reserved_key(key)
    })
}

pub(super) fn selected(transaction: &JournalTransaction) -> bool {
    transaction.records().iter().any(|record| {
        record.namespace() == RecordNamespace::DesiredState && codec::reserved_key(record.key())
    })
}

/// Checks selected payload headroom before the existing preview-map clone.
pub(super) fn bound_preview(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    transactions: &[JournalTransaction],
    limits: JournalLimits,
) -> Result<(), JournalError> {
    bound_preview_view(state, &PreflightTransactionViewV1::Ordinary(transactions), limits)
}

/// Borrows the current closed preflight view without copying any transaction.
pub(super) fn bound_preview_view(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    transactions: &PreflightTransactionViewV1<'_>,
    limits: JournalLimits,
) -> Result<(), JournalError> {
    if !has_dependencies(state)
        && !(0..transactions.len()).any(|index| selected(transactions.transaction(index)))
    {
        return Ok(());
    }

    let current = state.iter().try_fold(0_usize, |total, ((_, key), value)| {
        total.checked_add(key.len())
            .and_then(|bytes| bytes.checked_add(value.len()))
            .ok_or(JournalError::LimitExceeded("Delete preview payload"))
    })?;
    let additions = (0..transactions.len()).try_fold(0_usize, |total, index| {
        let transaction = transactions.transaction(index);
        transaction.records().iter().try_fold(total, |total, record| {
            total.checked_add(record.key().len())
                .and_then(|bytes| bytes.checked_add(record.value().map_or(0, <[u8]>::len)))
                .ok_or(JournalError::LimitExceeded("Delete preview payload"))
        })
    })?;
    let maximum = limits.maximum_materialized_bytes
        .checked_add(limits.maximum_transaction_bytes)
        .ok_or(JournalError::LimitExceeded("Delete preview payload"))?;
    if current > limits.maximum_materialized_bytes
        || current.checked_add(additions).is_none_or(|bytes| bytes > maximum)
    {
        return Err(JournalError::LimitExceeded("Delete preview payload"));
    }
    // This bounds current payload plus proposed retained copies. It excludes
    // map nodes, decoded protobuf temporaries and allocator/kernel funding.
    Ok(())
}

/// Validates the same real predecessor for append, preview and cold COMMIT.
pub(super) fn validate(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    transaction: &JournalTransaction,
    before_sequence: u64,
    limits: JournalLimits,
) -> Result<(), JournalError> {
    if !has_dependencies(state) && !selected(transaction) {
        return Ok(());
    }

    preserve_pending_members(state, transaction)?;
    if !selected(transaction) {
        return Ok(());
    }
    validate_transaction(transaction, limits)?;
    bound_preview(state, std::slice::from_ref(transaction), limits)?;

    let first = transaction.records().first().ok_or_else(invalid)?;
    if first.namespace() != RecordNamespace::DesiredState
        || !first.key().starts_with(codec::BATCH_PREFIX)
    {
        return Err(invalid());
    }
    let batch = DeleteBatchViewV1::decode(first.value().ok_or_else(invalid)?)
        .map_err(|_| invalid())?;
    if first.key() != codec::batch_key(batch.project(), batch.operation())
        || transaction.id() != &batch.transaction()
        || batch.before_sequence() != before_sequence
        || state.contains_key(&(RecordNamespace::DesiredState, first.key().to_vec()))
    {
        return Err(invalid());
    }

    #[cfg(target_os = "linux")]
    validate_admission(state, transaction, batch)?;
    #[cfg(not(target_os = "linux"))]
    return Err(JournalError::UnsupportedProtectedOpen);
    Ok(())
}

/// Preserves old Live preimages and every immutable pending dependency.
fn preserve_pending_members(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    transaction: &JournalTransaction,
) -> Result<(), JournalError> {
    for ((namespace, key), value) in state {
        if *namespace != RecordNamespace::DesiredState {
            continue;
        }
        if key.starts_with(codec::BATCH_PREFIX) {
            let batch = DeleteBatchViewV1::decode(value).map_err(|_| invalid())?;
            if key != &codec::batch_key(batch.project(), batch.operation()) {
                return Err(invalid());
            }
            if transaction.records().iter().any(|record| {
                (record.namespace() == RecordNamespace::Operation
                    && record.key() == batch.operation().as_bytes())
                    || (record.namespace() == RecordNamespace::DesiredState
                        && (record.key() == key
                            || batch.rows(0).any(|row| {
                                record.key() == codec::row_key(row, 0)
                            })))
            }) {
                return Err(JournalError::ProtectedBoundary);
            }
        } else if key.starts_with(codec::TOMBSTONE_PREFIX) || key.starts_with(codec::HANDOFF_PREFIX) {
            if transaction.records().iter().any(|record| {
                record.namespace() == *namespace && record.key() == key
            }) {
                return Err(JournalError::ProtectedBoundary);
            }
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_admission(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    transaction: &JournalTransaction,
    batch: DeleteBatchViewV1<'_>,
) -> Result<(), JournalError> {
    let records = transaction.records();
    let local_start: usize = if records.get(4).is_some_and(|record| {
        record.namespace() == RecordNamespace::OwnershipGate
    }) {
        5
    } else {
        4
    };
    let effects_start = local_start.checked_add(batch.count(0))
        .and_then(|offset| offset.checked_add(batch.count(2)))
        .and_then(|offset| offset.checked_add(1))
        .ok_or_else(invalid)?;
    if effects_start >= records.len() {
        return Err(invalid());
    }

    // W compares the retained native projection, but PUTs only a pending
    // overlay. Its predecessor remains untouched for audit and readback.
    for row in batch.rows(0) {
        require_projection(state, batch, row)?;
    }
    for row in batch.rows(1) {
        let namespace = RecordNamespace::from_byte(row[17])?;
        let key = codec::row_key(row, 1);
        let actual = state.get(&(namespace, key.to_vec()));
        if actual.is_some() != (row[20] == 1)
            || actual.is_some_and(|value| codec::native_value_digest(value) != row[24..56])
        {
            return Err(conflict());
        }
    }

    let mut offset = local_start;
    for resource in batch.rows(4) {
        let row = batch.rows(0)
            .find(|row| &row[..17] == resource)
            .ok_or_else(invalid)?;
        let value = codec::tombstone(batch, row);
        if codec::native_value_digest(&value) != row[68..100] {
            return Err(invalid());
        }
        let key = codec::tombstone_key(batch.project(), resource);
        if state.contains_key(&(RecordNamespace::DesiredState, key.clone())) {
            return Err(conflict());
        }
        require_put(records.get(offset), &key, &value)?;
        offset += 1;
    }
    for row in batch.rows(2) {
        let key = codec::row_key(row, 2);
        let before = codec::collection(batch.project(), row, false);
        if state.get(&(RecordNamespace::DesiredState, key.to_vec())).map(Vec::as_slice) != Some(before.as_slice()) {
            return Err(conflict());
        }
        require_put(records.get(offset), key, &codec::collection(batch.project(), row, true))?;
        offset += 1;
    }
    let marker = records.get(offset).ok_or_else(invalid)?;
    if marker.namespace() != RecordNamespace::DesiredState
        || marker.key() != codec::handoff_key(batch.project(), batch.operation())
    {
        return Err(invalid());
    }
    codec::validate_handoff(marker.value().ok_or_else(invalid)?, batch).map_err(|_| invalid())?;
    if state.contains_key(&(RecordNamespace::DesiredState, marker.key().to_vec())) {
        return Err(conflict());
    }

    crate::reconciler::validate_delete_batch_admission_records_v1(
        batch,
        transaction,
        local_start,
        effects_start,
    )
    .map_err(|_| JournalError::MalformedTransaction("invalid Delete batch admission metadata"))
}

#[cfg(target_os = "linux")]
fn require_projection(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    batch: DeleteBatchViewV1<'_>,
    row: &[u8],
) -> Result<(), JournalError> {
    use crate::controller_service::public_projection::{
        PublicProjectionKindV1 as Kind, PublicProjectionRecordV1, PublicProjectionResourceV1 as Resource,
        projection_key,
    };
    let kind = match row[0] {
        1 => Kind::Sandbox,
        2 => Kind::Execution,
        3 => Kind::Snapshot,
        4 => Kind::FilesystemView,
        5 => Kind::Attachment,
        _ => return Err(invalid()),
    };
    let identity: [u8; 16] = row[1..17].try_into().map_err(|_| invalid())?;
    let key = codec::row_key(row, 0);
    if key != projection_key(kind, identity) {
        return Err(invalid());
    }
    let value = state.get(&(RecordNamespace::DesiredState, key.to_vec())).ok_or_else(conflict)?;
    if codec::native_value_digest(value) != row[28..60] {
        return Err(conflict());
    }
    let projection = PublicProjectionRecordV1::from_retained_record_bytes(kind, identity, value)
        .map_err(|_| invalid())?;
    let generation = match projection.resource() {
        Resource::Sandbox(value) => value.desired.as_option().map(|desired| desired.generation),
        Resource::Execution(value) => Some(value.desired_generation),
        Resource::FilesystemView(value) => Some(value.desired_generation),
        Resource::Attachment(value) => Some(value.desired_generation),
        Resource::Snapshot(value) => Some(value.desired_generation),
        _ => None,
    };
    if projection.project() != batch.project() || generation != Some(codec::raw64(&row[20..28])) {
        return Err(conflict());
    }
    Ok(())
}

fn require_put(record: Option<&JournalRecord>, key: &[u8], value: &[u8]) -> Result<(), JournalError> {
    let record = record.ok_or_else(invalid)?;
    if record.namespace() != RecordNamespace::DesiredState
        || record.key() != key
        || record.value() != Some(value)
    {
        return Err(invalid());
    }
    Ok(())
}

fn invalid() -> JournalError {
    JournalError::MalformedRecord("invalid Delete batch native recipe")
}

fn conflict() -> JournalError {
    JournalError::MalformedTransaction("stale Delete batch member or collection")
}

/// Observes metadata only after the sole native parser validates COMMIT.
#[cfg(target_os = "linux")]
pub(super) struct NativeObserverV1 {
    transaction: [u8; 16],
    proof: Option<[u8; 64]>,
}

#[cfg(target_os = "linux")]
impl NativeObserverV1 {
    pub(super) fn observe(
        &mut self,
        transaction: &JournalTransaction,
        commit_sequence: u64,
        end_offset: u64,
        native_digest: &[u8],
    ) -> Result<(), JournalError> {
        if transaction.id() != &self.transaction {
            return Ok(());
        }
        if self.proof.is_some() || native_digest.len() != 32 || !selected(transaction) {
            return Err(invalid());
        }
        let mut proof = [0; 64];
        proof[..16].copy_from_slice(transaction.id());
        proof[16..48].copy_from_slice(native_digest);
        proof[48..56].copy_from_slice(&commit_sequence.to_be_bytes());
        proof[56..64].copy_from_slice(&end_offset.to_be_bytes());
        self.proof = Some(proof);
        Ok(())
    }
}

/// Retains first readback cause separately from a final original-owner debt.
#[cfg(target_os = "linux")]
#[derive(Debug, thiserror::Error)]
#[error("Delete native readback refused: {cause}")]
pub(crate) struct NativeReadbackErrorV1 {
    #[source]
    pub(crate) cause: JournalError,
    pub(crate) postcheck: Option<JournalError>,
}

#[cfg(target_os = "linux")]
impl From<JournalError> for NativeReadbackErrorV1 {
    fn from(cause: JournalError) -> Self {
        Self { cause, postcheck: None }
    }
}

#[cfg(target_os = "linux")]
impl Journal {
    /// Returns actual validated native COMMIT DATA while borrowing this writer.
    ///
    /// # Errors
    ///
    /// Refuses foreign fixed names/limits, missing batch/COMMIT, incomplete or
    /// compacted history, replay disagreement or original file/lock drift.
    /// The returned bytes cannot authenticate Source or authorize retirement.
    pub(crate) fn observe_delete_batch_native_proof_v1(
        &self,
        batch_bytes: &[u8],
    ) -> Result<[u8; 64], NativeReadbackErrorV1> {
        use super::runtime_deployment_history::ReadAtCursorV1;

        let batch = DeleteBatchViewV1::decode(batch_bytes).map_err(|_| invalid())?;
        self.require_delete_location()?;
        let witness = self.protected_writer_name_witness()?;
        let result = (|| {
            let key = codec::batch_key(batch.project(), batch.operation());
            if self.state.get(&(RecordNamespace::DesiredState, key)).map(Vec::as_slice)
                != Some(batch_bytes)
            {
                return Err(invalid());
            }
            bound_preview(&self.state, &[], self.limits)?;

            let mut observer = NativeObserverV1 {
                transaction: batch.transaction(),
                proof: None,
            };
            let mut reader = ReadAtCursorV1::new(self.storage.file(), witness.file.size);
            let replayed = replay_original_observed(
                &mut reader,
                self.limits,
                None,
                Some(DeploymentHistoryObserverV1::Delete(&mut observer)),
            )?;
            if replayed.durable_end != witness.file.size
                || replayed.next_sequence != self.next_sequence
                || replayed.committed_transactions != self.committed_transactions
                || replayed.transaction_ids != self.transaction_ids
                || replayed.state != self.state
                || replayed.idempotency != self.idempotency
                || replayed.materialized_bytes != self.materialized_bytes
                || replayed.q04_lower_history_present != self.q04_lower_history_present
                || replayed.source_history_compacted
            {
                return Err(invalid());
            }
            observer.proof.ok_or_else(invalid)
        })();

        let postcheck = self.require_delete_location()
            .and_then(|()| self.validate_protected_writer_name_witness(&witness));
        match (result, postcheck) {
            (Ok(proof), Ok(())) => Ok(proof),
            (Err(cause), postcheck) => Err(NativeReadbackErrorV1 {
                cause,
                postcheck: postcheck.err(),
            }),
            (Ok(_), Err(cause)) => Err(NativeReadbackErrorV1 { cause, postcheck: None }),
        }
    }

    fn require_delete_location(&self) -> Result<(), JournalError> {
        self.require_protected_named_location(
            Path::new("/var/lib/aos/sandboxd"),
            "controller.journal",
            self.protected_owner_uid()?,
            crate::controller_service::journal::production_journal_limits(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn retained_pending_batch() -> (BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>, Vec<u8>) {
        let bytes = codec::fixture_batch_v1(b"projection", b"retained before", 1);
        let batch = DeleteBatchViewV1::decode(&bytes).unwrap();
        let key = codec::batch_key(batch.project(), batch.operation());
        let state = BTreeMap::from([((RecordNamespace::DesiredState, key), bytes.clone())]);
        (state, bytes)
    }

    #[test]
    fn pending_batch_fences_exact_operation_and_live_preimage_without_global_freeze() {
        let (state, _) = retained_pending_batch();
        for record in [
            JournalRecord::put(RecordNamespace::Operation, vec![5; 16], b"terminal".to_vec()),
            JournalRecord::delete(RecordNamespace::Operation, vec![5; 16]),
            JournalRecord::put(RecordNamespace::DesiredState, b"projection".to_vec(), b"changed".to_vec()),
        ] {
            let transaction = JournalTransaction::new([20; 16], vec![record]).unwrap();
            assert!(matches!(validate(&state, &transaction, 2, JournalLimits::default()), Err(JournalError::ProtectedBoundary)));
        }

        let unrelated = JournalTransaction::new([21; 16], vec![
            JournalRecord::put(RecordNamespace::Operation, vec![22; 16], b"unrelated".to_vec()),
        ]).unwrap();
        assert!(validate(&state, &unrelated, 2, JournalLimits::default()).is_ok());
    }

    #[test]
    fn batch_native_watermark_and_foreign_marker_refuse_before_admission_decode() {
        let (_, bytes) = retained_pending_batch();
        let batch = DeleteBatchViewV1::decode(&bytes).unwrap();
        let transaction = JournalTransaction::new(batch.transaction(), vec![
            JournalRecord::put(RecordNamespace::DesiredState,
                codec::batch_key(batch.project(), batch.operation()), bytes.clone()),
        ]).unwrap();
        assert!(validate(&BTreeMap::new(), &transaction, 2, JournalLimits::default()).is_err());

        let marker_only = JournalTransaction::new([23; 16], vec![
            JournalRecord::put(RecordNamespace::DesiredState,
                codec::handoff_key(batch.project(), batch.operation()).to_vec(), vec![0; 160]),
        ]).unwrap();
        assert!(validate(&BTreeMap::new(), &marker_only, 1, JournalLimits::default()).is_err());
    }

    #[test]
    fn preview_checks_aggregate_payload_before_clone_but_ordinary_path_is_unchanged() {
        let (state, _) = retained_pending_batch();
        let maximum_materialized_bytes = state.iter().map(|((_, key), value)| key.len() + value.len()).sum();
        let limits = JournalLimits {
            maximum_materialized_bytes, maximum_transaction_bytes: 8,
            ..JournalLimits::default()
        };
        let transaction = JournalTransaction::new([24; 16], vec![
            JournalRecord::put(RecordNamespace::Operation, vec![25; 16], vec![26; 16]),
        ]).unwrap();

        assert!(bound_preview(&state, std::slice::from_ref(&transaction), limits).is_err());
        assert!(bound_preview(&BTreeMap::new(), &[transaction], limits).is_ok());
    }
}
