//! Compares the same strict terminal/pre-ACK recipe inside native COMMIT replay.
//!
//! The caller supplies only transactions already accepted by the sole native
//! parser and complete role-semantic checks. This observed DATA carries no file,
//! role, clock, account, native disposition or permission to publish success.

use super::{CreateStoppedPreAckTransactionDataV1, CreateStoppedTerminalTransactionDataV1,
    CreateStoppedTerminalDataErrorV1, CreateStoppedRecoveredTerminalDataV1,
    CreateStoppedRecoveredTerminalDataErrorV1};
use crate::domain_ledger::transaction::JournalTransaction;
use aos_sandbox_model::RecordNamespace;
use std::collections::BTreeMap;

/// Preserves strict comparison refusal separately from observer ordering.
#[derive(Debug, thiserror::Error)]
#[doc(hidden)]
pub enum CreateStoppedNativeObservationErrorV2 {
    /// The exact comparison recipe was repeated or never observed.
    #[error("the selected Create native transaction is missing or repeated")]
    Ordering,
    /// The existing strict terminal/pre-ACK predicate refused the actual COMMIT.
    #[error(transparent)]
    Comparison(#[from] CreateStoppedTerminalDataErrorV1),
    /// The distinct exact recovered joint4 predicate refused the actual COMMIT.
    #[error(transparent)]
    Recovered(#[from] CreateStoppedRecoveredTerminalDataErrorV1),
}

/// Retains one exact comparison recipe and whether its COMMIT was observed.
///
/// A genuine reader must independently establish full replay through EOF and
/// all native posts before lending historical proof. This value alone grants
/// no custody, acceptance, completion, recovery or lifecycle authority.
#[doc(hidden)]
pub struct CreateStoppedNativeObservationDataV2<'rows> {
    transaction: SelectedTransactionV2<'rows>,
    observed: bool,
}

enum SelectedTransactionV2<'rows> {
    Terminal(CreateStoppedTerminalTransactionDataV1<'rows>),
    PreAck(CreateStoppedPreAckTransactionDataV1<'rows>),
    Recovered(CreateStoppedRecoveredTerminalDataV1<'rows>),
}

impl<'rows> CreateStoppedNativeObservationDataV2<'rows> {
    /// Selects the ordinary or recovered recipe from the same complete flat state.
    ///
    /// The immutable admission and completed Recover row select comparison DATA
    /// only. A genuine reader still must observe the selected COMMIT during full
    /// native replay and settle its independent currentness and disposal posts.
    /// This scan borrows rows and decodes only fixed-width Operation metadata;
    /// it creates no map, index, request model or additional dynamic allocation.
    ///
    /// # Errors
    /// Refuses malformed admission framing, a missing operation, multiple completed
    /// admissions for the same Create, or a noncanonical metadata completion.
    pub fn terminal_from_state_v2(
        terminal: CreateStoppedTerminalTransactionDataV1<'rows>,
        state: &'rows BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    ) -> Result<Self, CreateStoppedRecoveredTerminalDataErrorV1> {
        use crate::domain_ledger::{
            operation::decode_operation,
            public_operation::OperationState,
            provisioning_root::finality_recover::{
                CreateFinalityObservationAdmissionDataV1 as Admission,
                public_operation::MetadataCompleteDataErrorV1,
            },
        };

        let mut selected = None;
        for ((namespace, key), bytes) in state {
            if *namespace != RecordNamespace::OperatorRecovery
                || !Admission::is_admission_key_v1(key) {
                continue;
            }
            Admission::require_record_v1(key, bytes)
                .map_err(MetadataCompleteDataErrorV1::from)?;
            let admission = Admission::decode_v1(bytes)
                .map_err(MetadataCompleteDataErrorV1::from)?;
            if admission.target != *terminal.operation.as_bytes() { continue; }

            // A borrowed search avoids allocating a temporary Vec for the key.
            let operation = state.iter().find_map(|((namespace, key), value)| {
                (*namespace == RecordNamespace::Operation
                    && key.as_slice() == admission.operation).then_some(value.as_slice())
            }).ok_or(CreateStoppedRecoveredTerminalDataErrorV1::Mismatch)?;
            let decoded = decode_operation(operation)
                .map_err(MetadataCompleteDataErrorV1::from)?;
            if decoded.state() != OperationState::Succeeded { continue; }
            if selected.replace((admission, operation)).is_some() {
                return Err(CreateStoppedRecoveredTerminalDataErrorV1::Mismatch);
            }
        }

        match selected {
            None => Ok(Self::terminal_v2(terminal)),
            Some((admission, operation)) => Ok(Self::recovered_v2(
                CreateStoppedRecoveredTerminalDataV1::from_data_v1(
                    terminal, admission, operation)?)),
        }
    }

    /// Selects an already checked ordinary three-row terminal DATA recipe.
    #[must_use]
    pub fn terminal_v2(transaction: CreateStoppedTerminalTransactionDataV1<'rows>) -> Self {
        Self { transaction: SelectedTransactionV2::Terminal(transaction), observed: false }
    }

    /// Selects an already checked strict one-Effect pre-ACK DATA recipe.
    #[must_use]
    pub fn pre_ack_v2(transaction: CreateStoppedPreAckTransactionDataV1<'rows>) -> Self {
        Self { transaction: SelectedTransactionV2::PreAck(transaction), observed: false }
    }

    /// Selects only a checked distinct recovered joint4 comparison recipe.
    #[must_use]
    pub fn recovered_v2(transaction: CreateStoppedRecoveredTerminalDataV1<'rows>) -> Self {
        Self { transaction: SelectedTransactionV2::Recovered(transaction), observed: false }
    }

    /// Returns the exact selected normal, pre-ACK or recovered transaction ID.
    ///
    /// This identity is comparison DATA and grants no native observation.
    #[must_use]
    pub fn selected_transaction_id_v2(&self) -> [u8; 16] {
        match &self.transaction {
            SelectedTransactionV2::Terminal(value) => value.transaction_id_v1(),
            SelectedTransactionV2::PreAck(value) => value.transaction_id_v1(),
            SelectedTransactionV2::Recovered(value) => value.transaction_id_v1(),
        }
    }

    /// Compares only the exact selected actual COMMIT through the sole predicate.
    ///
    /// # Errors
    /// Preserves canonical member/decoder refusal and rejects a duplicate
    /// selected transaction. Unrelated transactions grant no observation.
    pub fn observe_v2(&mut self, transaction: &JournalTransaction)
        -> Result<(), CreateStoppedNativeObservationErrorV2> {
        let identity = self.selected_transaction_id_v2();
        if transaction.id() != &identity { return Ok(()); }
        if self.observed { return Err(CreateStoppedNativeObservationErrorV2::Ordering); }
        match &self.transaction {
            SelectedTransactionV2::Terminal(value) => value.require_transaction_v1(transaction)
                .map_err(CreateStoppedNativeObservationErrorV2::Comparison),
            SelectedTransactionV2::PreAck(value) => value.require_transaction_v1(transaction)
                .map_err(CreateStoppedNativeObservationErrorV2::Comparison),
            SelectedTransactionV2::Recovered(value) => value.require_transaction_v1(transaction)
                .map_err(CreateStoppedNativeObservationErrorV2::Recovered),
        }?;
        self.observed = true;
        Ok(())
    }

    /// Requires that this exact strict comparison occurred during actual replay.
    ///
    /// This supplies comparison DATA only. Native EOF, physical currentness and
    /// independently owed post/disposal evidence remain with the actual reader.
    ///
    /// # Errors
    /// Refuses when no complete matching COMMIT has been observed.
    pub fn require_observed_v2(&self) -> Result<(), CreateStoppedNativeObservationErrorV2> {
        if self.observed { Ok(()) } else { Err(CreateStoppedNativeObservationErrorV2::Ordering) }
    }
}
