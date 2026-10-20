//! Compares the strict recovered joint4 without altering normal Create history.
//!
//! This grammar preserves the sole normal three-row predicate and adds exactly
//! the new MetadataComplete operation. Its identity uses immutable rows so a
//! later Start projection cannot erase the historical COMMIT selection. These
//! are comparison DATA; full replay, native posts and authority remain external.

use aos_sandbox_core::RecordNamespace;

use super::{CreateStoppedTerminalDataErrorV1, CreateStoppedTerminalTransactionDataV1};
use crate::domain_ledger::provisioning_root::finality_recover::{
    CreateFinalityObservationAdmissionDataV1,
    public_operation::{MetadataCompleteDataErrorV1, metadata_complete_joint_transaction_id_v1,
        require_metadata_complete_completed_operation_v1},
};
use crate::domain_ledger::transaction::JournalTransaction;

/// Preserves the exact old terminal and new metadata-operation comparison causes.
#[derive(Debug, thiserror::Error)]
pub enum CreateStoppedRecoveredTerminalDataErrorV1 {
    /// The unchanged historical three-row terminal comparison refused.
    #[error(transparent)]
    Terminal(#[from] CreateStoppedTerminalDataErrorV1),
    /// The new operation or immutable recovery admission differs.
    #[error(transparent)]
    Metadata(#[from] MetadataCompleteDataErrorV1),
    /// Exact joint transaction identity, order, count or final operation differs.
    #[error("recovered Create terminal transaction differs")]
    Mismatch,
}

/// Borrows one checked immutable terminal and its explicit metadata completion.
pub struct CreateStoppedRecoveredTerminalDataV1<'rows> {
    terminal: CreateStoppedTerminalTransactionDataV1<'rows>,
    admission: CreateFinalityObservationAdmissionDataV1<'rows>,
    operation: &'rows [u8],
    transaction: [u8; 16],
}

impl<'rows> CreateStoppedRecoveredTerminalDataV1<'rows> {
    /// Checks immutable selection DATA without constructing a native proof.
    ///
    /// # Errors
    /// Refuses a different target/project or noncanonical MetadataComplete result.
    pub fn from_data_v1(
        terminal: CreateStoppedTerminalTransactionDataV1<'rows>,
        admission: CreateFinalityObservationAdmissionDataV1<'rows>,
        operation: &'rows [u8],
    ) -> Result<Self, CreateStoppedRecoveredTerminalDataErrorV1> {
        require_metadata_complete_completed_operation_v1(admission, operation)?;
        if terminal.operation.as_bytes() != &admission.target
            || terminal.project.as_bytes() != &admission.project
        {
            return Err(CreateStoppedRecoveredTerminalDataErrorV1::Mismatch);
        }
        let transaction = metadata_complete_joint_transaction_id_v1(
            &terminal.transaction_id_v1(),
            &admission.key_v1(),
            operation,
        );
        Ok(Self {
            terminal,
            admission,
            operation,
            transaction,
        })
    }

    /// Returns only the exact immutable joint COMMIT selection identity.
    #[must_use]
    pub const fn transaction_id_v1(&self) -> [u8; 16] {
        self.transaction
    }

    /// Requires the unchanged old three members and exact new fourth operation.
    ///
    /// # Errors
    /// Refuses another ID, extra/deleted/reordered member or any semantic mismatch.
    pub fn require_transaction_v1(
        &self,
        transaction: &JournalTransaction,
    ) -> Result<(), CreateStoppedRecoveredTerminalDataErrorV1> {
        let [_, _, _, recovery] = transaction.records() else {
            return Err(CreateStoppedRecoveredTerminalDataErrorV1::Mismatch);
        };
        if transaction.id() != &self.transaction
            || recovery.namespace() != RecordNamespace::Operation
            || recovery.key() != self.admission.operation
            || recovery.value() != Some(self.operation)
        {
            return Err(CreateStoppedRecoveredTerminalDataErrorV1::Mismatch);
        }
        self.terminal
            .require_terminal_rows_v2(&transaction.records()[..3])?;
        Ok(())
    }
}
