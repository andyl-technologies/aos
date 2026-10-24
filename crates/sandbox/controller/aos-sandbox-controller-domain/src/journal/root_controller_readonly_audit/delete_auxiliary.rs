//! Retains selected auxiliary members from the actual Root Source native audit.
//!
//! Capture is subordinate to the same file/cursor and prepaid captured extent.
//! It validates framing only; the later Domain auxiliary-history kernel owns
//! complete Operation/Batch transitions. No independent parser or Journal opens.

use super::*;
use aos_sandbox_broker::canonical_journal::CanonicalCommitReadViewV1;
use aos_sandbox_model::{OperationId, ProjectId};
use aos_sandbox_protocol::domain_ledger::lifecycle_auxiliary::{
    LIFECYCLE_PROTECTED_KEY_PREFIX_V1, borrow_lifecycle_auxiliary_member_data_v1,
};
use aos_sandbox_protocol::domain_ledger::records::borrowed::borrow_protected_key_data_v1;

pub(crate) struct RootDeleteAuxiliaryRowDataV3 {
    pub(crate) key: Vec<u8>,
    pub(crate) value: Vec<u8>,
    pub(crate) transaction: [u8; 16],
    pub(crate) native: [u8; 64],
}

pub(super) struct DeleteAuxiliaryCaptureV3 {
    project: ProjectId,
    operation: OperationId,
    rows: Vec<RootDeleteAuxiliaryRowDataV3>,
    returned: Option<Result<(), aos_sandbox_protocol::domain_ledger::DomainLedgerDataError>>,
}

impl DeleteAuxiliaryCaptureV3 {
    pub(super) fn new(project: ProjectId, operation: OperationId) -> Self {
        Self {
            project,
            operation,
            rows: Vec::new(),
            returned: None,
        }
    }

    pub(super) fn receiving_demand_v3(&self, bytes: u64) -> Result<ResourceVector, JournalError> {
        let invalid = || JournalError::JournalTooLarge;
        let bytes = usize::try_from(bytes).map_err(|_| invalid())?;
        let rows = bytes / aos_sandbox_journal::framing::HEADER_BYTES;
        let capacity = rows
            .checked_mul(2)
            .map(|count| count.max(4))
            .ok_or_else(invalid)?;
        // Native framing strictly contains every key/value pair copied here.
        // Vec's first allocation and geometric spare remain separate carriers.
        let memory = bytes
            .checked_mul(2)
            .and_then(|size| {
                size.checked_add(capacity.checked_mul(size_of::<RootDeleteAuxiliaryRowDataV3>())?)
            })
            .and_then(|size| size.checked_add(2 * size_of::<Self>()))
            .ok_or_else(invalid)?;
        Ok(ResourceVector::ZERO.with(
            D::MemoryBytes,
            u64::try_from(memory).map_err(|_| invalid())?,
        ))
    }

    pub(super) fn observe_commit_v3(
        &mut self,
        commit: &CanonicalCommitReadViewV1<'_>,
    ) -> Result<(), JournalError> {
        if self.returned.as_ref().is_some_and(Result::is_err) {
            return Err(JournalError::ProtectedBoundary);
        }
        self.returned = Some((|| {
            for row in commit.transaction().records().iter().filter(|row| {
                row.namespace() == RecordNamespace::DesiredState
                    && row.key().starts_with(LIFECYCLE_PROTECTED_KEY_PREFIX_V1)
            }) {
                let (kind, identity) =
                    borrow_protected_key_data_v1(row.key(), LIFECYCLE_PROTECTED_KEY_PREFIX_V1)?;
                if kind != 5
                    || identity.len() != 48
                    || identity[..16] != self.project.as_bytes()[..]
                    || identity[32..] != self.operation.as_bytes()[..]
                {
                    continue;
                }
                let value = row.value().ok_or(
                    aos_sandbox_protocol::domain_ledger::DomainLedgerDataError::NonCanonicalRecord,
                )?;
                borrow_lifecycle_auxiliary_member_data_v1(
                    row.key(),
                    value,
                    commit.transaction().id(),
                )?;
                let native = aos_sandbox_protocol::domain_ledger::delete_batch::encode_native_commit_data_v1(
                    *commit.transaction().id(), commit.commit_sequence(), commit.coordinates().offset, commit.commit_payload())
                    .map_err(|_| aos_sandbox_protocol::domain_ledger::DomainLedgerDataError::NonCanonicalRecord)?;
                self.rows.push(RootDeleteAuxiliaryRowDataV3 {
                    key: row.key().to_vec(),
                    value: value.to_vec(),
                    transaction: *commit.transaction().id(),
                    native,
                });
            }
            Ok(())
        })());
        if matches!(self.returned, Some(Ok(()))) {
            Ok(())
        } else {
            Err(JournalError::ProtectedBoundary)
        }
    }

    pub(super) fn rows_v3(&self) -> Result<&[RootDeleteAuxiliaryRowDataV3], JournalError> {
        if !matches!(self.returned, Some(Ok(()))) {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(&self.rows)
    }

    pub(super) fn failure(
        &self,
    ) -> Option<&aos_sandbox_protocol::domain_ledger::DomainLedgerDataError> {
        self.returned.as_ref()?.as_ref().err()
    }
}
