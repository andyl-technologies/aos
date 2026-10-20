//! Selects final Delete COMMIT DATA while preserving the immutable Batch2 cut.

use super::*;
use aos_sandbox_protocol::domain_ledger::delete_root::source_current::require_source_delete_terminal_operation_frame_v4;
use std::collections::BTreeMap;

#[derive(Clone, Copy)]
struct BatchV4 {
    key: [u8; AUXILIARY_KEY_BYTES],
    native: [u8; 64],
    digest: [u8; 32],
}

#[derive(Default)]
pub(super) struct TerminalReplayDataV4 {
    batch: Option<BatchV4>,
    operation: Option<([u8; AUXILIARY_KEY_BYTES], [u8; 16], [u8; 32])>,
}

impl TerminalReplayDataV4 {
    pub(super) fn observe_commit_v4(
        &mut self,
        query: SourceDeleteCurrentQueryDataV1,
        commit: &CanonicalCommitReadViewV1<'_>,
    ) -> Result<bool, PendingErrorV1> {
        self.operation = None;
        let transaction = commit.transaction();
        for row in transaction.records().iter().filter(|row| {
            row.namespace() == RecordNamespace::DesiredState
                && row.key().starts_with(LIFECYCLE_PROTECTED_KEY_PREFIX_V1)
        }) {
            let (kind, _) =
                borrow_protected_key_data_v1(row.key(), LIFECYCLE_PROTECTED_KEY_PREFIX_V1)?;
            if kind != 5 {
                continue;
            }
            let Some(value) = row.value() else {
                continue;
            };
            let frame =
                borrow_lifecycle_auxiliary_member_data_v1(row.key(), value, transaction.id())?;
            if frame.format != LifecycleAuxiliaryEnvelopeFormatV1::DeleteBatch
                || frame.kind != 6
                || frame.project.as_bytes() != &query.project
                || frame.operation.as_bytes() != &query.operation
            {
                continue;
            }
            let batch = LifecycleDeleteBatchRecordViewDataV3::decode(frame.payload)?;
            if batch.state != 2
                || source_delete_controller_committed_batch_digest_v3(frame.payload)? != query.batch
            {
                continue;
            }
            // A second Batch2 transaction cannot replace the immutable historical
            // source cut, even if it repeats the same passive payload.
            if self.batch.is_some() {
                return Err(SourceDeleteCurrentDataErrorV1::Association.into());
            }
            self.batch = Some(BatchV4 {
                key: row
                    .key()
                    .try_into()
                    .map_err(|_| SourceDeleteCurrentDataErrorV1::Association)?,
                native: encode_native_commit_data_v1(
                    *transaction.id(),
                    commit.commit_sequence(),
                    commit.coordinates().offset,
                    commit
                        .commit_digest_data_v4()
                        .map_err(JournalError::from_ordinary_native_v1)?,
                )?,
                digest: *frame.digest.as_bytes(),
            });
        }

        let [operation, removal] = transaction.records() else {
            return Ok(false);
        };
        if self.batch.is_none()
            || operation.namespace() != RecordNamespace::DesiredState
            || !operation
                .key()
                .starts_with(LIFECYCLE_PROTECTED_KEY_PREFIX_V1)
            || removal.namespace() != RecordNamespace::SourceDomainPolicyHold
            || removal.key() != crate::source_policy_hold::DELETE_PENDING_KEY
            || removal.value().is_some()
        {
            return Ok(false);
        }
        let Some(value) = operation.value() else {
            return Ok(false);
        };
        let (kind, _) =
            borrow_protected_key_data_v1(operation.key(), LIFECYCLE_PROTECTED_KEY_PREFIX_V1)?;
        if kind != 5 {
            return Ok(false);
        }
        let frame =
            borrow_lifecycle_auxiliary_member_data_v1(operation.key(), value, transaction.id())?;
        if frame.format != LifecycleAuxiliaryEnvelopeFormatV1::DeleteBatch
            || frame.kind != 0
            || frame.project.as_bytes() != &query.project
            || frame.operation.as_bytes() != &query.operation
            || frame.declared_count != 1
            || frame.declared_members != 1
        {
            return Ok(false);
        }
        let digest = require_source_delete_terminal_operation_frame_v4(
            frame.payload,
            &query.project,
            &query.operation,
        )?;
        if frame.operation_record.as_bytes() != &digest {
            return Err(SourceDeleteCurrentDataErrorV1::Association.into());
        }
        self.operation = Some((
            operation
                .key()
                .try_into()
                .map_err(|_| SourceDeleteCurrentDataErrorV1::Association)?,
            *transaction.id(),
            *frame.digest.as_bytes(),
        ));
        Ok(true)
    }

    pub(super) fn finish_prefix_v4(
        &self,
        query: SourceDeleteCurrentQueryDataV1,
        state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    ) -> Result<(), PendingErrorV1> {
        let invalid = || SourceDeleteCurrentDataErrorV1::Association;
        let hold = crate::source_policy_hold::current_state(state)?;
        if hold.delete_pending.is_some()
            || hold.q04_pending.is_some()
            || hold.v8_pending.is_some()
            || hold.hold.is_some_and(|hold| hold.is_held())
            || state.contains_key(&(
                RecordNamespace::SourceDomainPolicyHold,
                crate::source_policy_hold::DELETE_PENDING_KEY.to_vec(),
            ))
        {
            return Err(invalid().into());
        }

        let batch = self.batch.as_ref().ok_or_else(invalid)?;
        let bytes = state
            .get(&(RecordNamespace::DesiredState, batch.key.to_vec()))
            .ok_or_else(invalid)?;
        let transaction: [u8; 16] = batch.native[..16].try_into().map_err(|_| invalid())?;
        let frame = borrow_lifecycle_auxiliary_member_data_v1(&batch.key, bytes, &transaction)?;
        if frame.digest.as_bytes() != &batch.digest
            || source_delete_controller_committed_batch_digest_v3(frame.payload)? != query.batch
        {
            return Err(invalid().into());
        }

        let (key, transaction, digest) = self.operation.as_ref().ok_or_else(invalid)?;
        let bytes = state
            .get(&(RecordNamespace::DesiredState, key.to_vec()))
            .ok_or_else(invalid)?;
        let frame = borrow_lifecycle_auxiliary_member_data_v1(key, bytes, transaction)?;
        if frame.digest.as_bytes() != digest {
            return Err(invalid().into());
        }
        require_source_delete_terminal_operation_frame_v4(
            frame.payload,
            &query.project,
            &query.operation,
        )?;
        Ok(())
    }

    pub(super) fn historical_batch_native_v4(
        &self,
    ) -> Result<[u8; 64], SourceDeleteCurrentDataErrorV1> {
        self.batch
            .map(|batch| batch.native)
            .ok_or(SourceDeleteCurrentDataErrorV1::Native)
    }
}
