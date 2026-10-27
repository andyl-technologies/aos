//! Records finite recovered subdivisions of the already precharged baseline.
//!
//! ```text
//! AOSRFS02 | purpose1 | reserved7 | enrollment96 | recipient16 |
//! baseline176 | chargedBefore176 | chargedAfter176 | complete176 |
//! declaredMaximum176 | originalCNext8 | originalCEnd8 | checksum32
//! key = r | H(enrollment | recipient | purpose)[..16]
//! ```
//!
//! A checksum or decoded balance does not prove a native debit. The genuine
//! same-B issuer captures both Core balances inside its actual debit, then the
//! same C publishes both rows inside fresh native/Source/clock bookends. Root
//! independently reads those exact rows, the recipient and complete bank.

use super::*;
use sha2::{Digest as _, Sha256};

pub(super) const PREFIX: u8 = b'r';
mod common;

#[cfg(test)]
mod tests;
/// Specifies the complete canonical recovered-subdivision row width.
pub const RECOVERED_OPERATION_FUNDING_BYTES_V1: usize = 1056;

/// Selects exactly one permanently funded recovered operation purpose.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveredOperationFundingPurposeV1 {
    /// Subdivides the successor's remaining baseline for Delete.
    Delete,
    /// Subdivides the successor's remaining baseline for Execution.
    Execution,
}

impl RecoveredOperationFundingPurposeV1 {
    fn tag(self) -> u8 { match self { Self::Delete => 17, Self::Execution => 18 } }
    fn decode(tag: u8) -> Result<Self, ResourceBankDataError> {
        match tag { 17 => Ok(Self::Delete), 18 => Ok(Self::Execution),
            _ => Err(ResourceBankDataError::CorruptLedger) }
    }
    fn claim_purpose(self) -> ClaimPurpose {
        match self { Self::Delete => ClaimPurpose::DeleteOperationIntake,
            Self::Execution => ClaimPurpose::ExecutionOperationIntake }
    }
    fn declaration_id(self, enrollment: EnrollmentIdentity) -> [u8; 16] {
        bootstrap::account_id(enrollment, match self {
            Self::Delete => b"controller-delete-operation-intake-v1",
            Self::Execution => b"controller-execution-operation-intake-v1",
        })
    }
}

/// Carries complete historical debit comparisons without issuing an intake.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveredOperationFundingDataV1 {
    /// Selects the closed recovered subdivision.
    pub purpose: RecoveredOperationFundingPurposeV1,
    /// Binds the original shared-bank enrollment.
    pub enrollment: EnrollmentIdentity,
    /// Binds the exact funded Controller recipient invocation.
    /// Historical replay may resolve its current or immutable archived range row;
    /// that lookup does not make an archived recipient current.
    pub recipient: [u8; 16],
    /// Gives the same original baseline B.
    pub baseline: ResourceVector,
    /// Gives actual Core charged usage immediately before this native debit.
    pub charged_before: ResourceVector,
    /// Gives actual Core charged usage immediately after this native debit.
    pub charged_after: ResourceVector,
    /// Gives the complete resident-plus-flight amount permanently debited.
    pub complete: ResourceVector,
    /// Gives the immutable image's maximum declaration for this purpose.
    pub declared: ResourceVector,
    /// Gives actual C NEXT captured before the native debit.
    pub controller_next: u64,
    /// Gives actual durable C end captured before the native debit.
    pub controller_end: u64,
}

impl RecoveredOperationFundingDataV1 {
    fn require_canonical(self) -> Result<(), ResourceBankDataError> {
        common::require_canonical_v2(self.common_v2(), Some(self.declared))
    }

    fn common_v2(self) -> common::FundingCommonDataV2 {
        common::FundingCommonDataV2 {
            purpose: self.purpose.tag(), enrollment: self.enrollment, recipient: self.recipient,
            baseline: self.baseline, charged_before: self.charged_before, charged_after: self.charged_after,
            complete: self.complete, controller_next: self.controller_next, controller_end: self.controller_end,
        }
    }

    /// Encodes every canonical comparison field through the sole vector codec.
    ///
    /// # Errors
    /// Refuses invalid identity, debit equation, capacity or native coordinates.
    pub fn encode_v1(self) -> Result<[u8; RECOVERED_OPERATION_FUNDING_BYTES_V1], ResourceBankDataError> {
        let mut bytes = [0; RECOVERED_OPERATION_FUNDING_BYTES_V1];
        common::encode_into_v2(self.common_v2(), Some(self.declared), &mut bytes)?;
        Ok(bytes)
    }

    /// Decodes the sole version-two declared-subdivision shape.
    ///
    /// # Errors
    /// Refuses obsolete magic, Stop shape, checksum, role or balance errors.
    pub fn decode_v1(bytes: &[u8]) -> Result<Self, ResourceBankDataError> {
        let (common, declared) = common::decode_v2(bytes)?;
        let row = Self {
            purpose: RecoveredOperationFundingPurposeV1::decode(common.purpose)?,
            enrollment: common.enrollment, recipient: common.recipient,
            baseline: common.baseline, charged_before: common.charged_before,
            charged_after: common.charged_after, complete: common.complete,
            declared: declared.ok_or(ResourceBankDataError::CorruptLedger)?,
            controller_next: common.controller_next, controller_end: common.controller_end,
        };
        row.require_canonical()?;
        Ok(row)
    }

    /// Returns the canonical finite row key without creating its writer.
    pub fn key_v1(self) -> [u8; 17] {
        common::key_v2(self.enrollment, self.recipient, self.purpose.tag())
    }

    /// Compares the complete actual protected row and its whole-bank relation.
    ///
    /// # Errors
    /// Refuses missing, substituted, malformed or unbound subdivisions.
    pub fn require_replayed_v1(self, state: &State) -> Result<(), ResourceBankDataError> {
        self.require_canonical()?;
        let key = self.key_v1();
        let mut id = [0; 16];
        id.copy_from_slice(&key[1..]);
        if replay::record_bytes(state, PREFIX, id) != Some(self.encode_v1()?.as_slice()) {
            return Err(ResourceBankDataError::Conflict);
        }
        self.require_bank_binding_v1(state)
    }

    fn require_bank_binding_v1(self, state: &State) -> Result<(), ResourceBankDataError> {
        let recipient = recipient::controller_recipient_for_invocation_v2(state, self.enrollment, self.recipient)?;
        if recipient.generation() == 0 || recipient.recipient() != self.recipient
            || recipient.charged_baseline_v1()? != self.baseline {
            return Err(ResourceBankDataError::CorruptLedger);
        }
        // The old declaration is a maximum comparison only. Its reservation,
        // unknown spending and claim identity never become recovered funding.
        let declaration = codec::decode_claim(replay::record_bytes(state, replay::CLAIM_PREFIX,
            self.purpose.declaration_id(self.enrollment)).ok_or(ResourceBankDataError::CorruptLedger)?)?;
        if declaration.enrollment != self.enrollment || declaration.purpose != self.purpose.claim_purpose()
            || declaration.amount != self.declared {
            return Err(ResourceBankDataError::CorruptLedger);
        }
        self.charged_before.checked_sub(recipient.outside_allowance_v2()?)?;
        Ok(())
    }
}

/// Compares the exact ordered pair of actual same-recipient Core debits.
///
/// # Errors
/// Refuses another role/order, native cut, baseline, recipient or prior debt.
pub fn require_recovered_funding_pair_data_v1(pair: &[RecoveredOperationFundingDataV1; 2])
    -> Result<(), ResourceBankDataError> {
    for row in pair { row.require_canonical()?; }
    let [delete, execution] = pair;
    if delete.purpose != RecoveredOperationFundingPurposeV1::Delete
        || execution.purpose != RecoveredOperationFundingPurposeV1::Execution
        || delete.enrollment != execution.enrollment || delete.recipient != execution.recipient
        || delete.baseline != execution.baseline || delete.charged_after != execution.charged_before
        || (delete.controller_next, delete.controller_end) != (execution.controller_next, execution.controller_end) {
        return Err(ResourceBankDataError::CorruptLedger);
    }
    Ok(())
}

pub(super) fn require_pair_replayed_v1(state: &State, row: RecoveredOperationFundingDataV1)
    -> Result<(), ResourceBankDataError> {
    let other_purpose = match row.purpose { RecoveredOperationFundingPurposeV1::Delete => RecoveredOperationFundingPurposeV1::Execution,
        RecoveredOperationFundingPurposeV1::Execution => RecoveredOperationFundingPurposeV1::Delete };
    let other_key = RecoveredOperationFundingDataV1 { purpose: other_purpose, ..row }.key_v1();
    let mut other_id = [0; 16];
    other_id.copy_from_slice(&other_key[1..]);
    let other = RecoveredOperationFundingDataV1::decode_v1(
        replay::record_bytes(state, PREFIX, other_id).ok_or(ResourceBankDataError::CorruptLedger)?)?;
    let pair = match row.purpose { RecoveredOperationFundingPurposeV1::Delete => [row, other],
        RecoveredOperationFundingPurposeV1::Execution => [other, row] };
    require_recovered_funding_pair_data_v1(&pair)?;
    for member in pair { member.require_replayed_v1(state)?; }
    Ok(())
}

fn pair_transaction_id_data_v1(pair: &[RecoveredOperationFundingDataV1; 2])
    -> Result<[u8; 16], ResourceBankDataError> {
    require_recovered_funding_pair_data_v1(pair)?;
    let digest = Sha256::new().chain_update(b"aos.controller.recovered-funding.transaction.v1\0")
        .chain_update(pair[0].encode_v1()?).chain_update(pair[1].encode_v1()?).finalize();
    let mut id = [0; 16];
    id.copy_from_slice(&digest[..16]);
    if id == [0; 16] { return Err(ResourceBankDataError::Conflict); }
    Ok(id)
}

/// Encodes the finite paired metadata transaction after the caller's payment.
///
/// This pure DATA factory creates no native debit, writer or publication proof.
///
/// # Errors
/// Refuses another purpose, recipient, debit order or canonical transaction.
pub fn recovered_funding_pair_transaction_data_v1(pair: &[RecoveredOperationFundingDataV1; 2])
    -> Result<JournalTransaction, ResourceBankDataError> {
    let id = pair_transaction_id_data_v1(pair)?;
    let records = pair.iter().map(|row| {
        Ok(JournalRecord::put(RecordNamespace::ControllerResourceReservation,
            row.key_v1().to_vec(), row.encode_v1()?.to_vec()))
    }).collect::<Result<Vec<_>, ResourceBankDataError>>()?;
    Ok(JournalTransaction::new(id, records)?)
}

/// Checks exact first publication against the actual transaction BEGIN frontier.
///
/// Unrelated transactions remain unchanged. Actual checkpoint restoration uses
/// the same complete-state validator after its genuine compaction entrance;
/// it does not pretend the old funding cut is the new checkpoint's BEGIN.
///
/// # Errors
/// Refuses partial, reordered, overwritten, deleted or unbound funding rows.
pub fn validate_recovered_funding_transaction_v1(state: &State, transaction: &JournalTransaction,
    begin_next: u64, begin_end: u64) -> Result<(), ResourceBankDataError> {
    let selected = transaction.records().iter().any(|record| {
        record.namespace() == RecordNamespace::ControllerResourceReservation
            && record.key().first() == Some(&PREFIX)
    });
    if !selected { return Ok(()); }
    if transaction.records().len() != 2 { return Err(ResourceBankDataError::CorruptLedger); }
    let decode = |index: usize| -> Result<RecoveredOperationFundingDataV1, ResourceBankDataError> {
        let record = &transaction.records()[index];
        if record.namespace() != RecordNamespace::ControllerResourceReservation {
            return Err(ResourceBankDataError::CorruptLedger);
        }
        let row = RecoveredOperationFundingDataV1::decode_v1(record.value()
            .ok_or(ResourceBankDataError::CorruptLedger)?)?;
        if record.key() != row.key_v1() || (row.controller_next, row.controller_end) != (begin_next, begin_end) {
            return Err(ResourceBankDataError::CorruptLedger);
        }
        let mut id = [0; 16];
        id.copy_from_slice(&row.key_v1()[1..]);
        if replay::record_bytes(state, PREFIX, id).is_some() {
            return Err(ResourceBankDataError::Conflict);
        }
        row.require_bank_binding_v1(state)?;
        Ok(row)
    };
    let pair = [decode(0)?, decode(1)?];
    require_recovered_funding_pair_data_v1(&pair)?;
    if transaction.id() != &pair_transaction_id_data_v1(&pair)?
        || replay::validate(state)? != Some(pair[0].enrollment) {
        return Err(ResourceBankDataError::CorruptLedger);
    }
    Ok(())
}

mod stop_seed;
pub use stop_seed::{RecoveredLifecycleStopFundingDataV2, RECOVERED_LIFECYCLE_STOP_SEED_BYTES_V2};
mod cleanup_seed;
pub use cleanup_seed::{RecoveredHostStopCleanupFundingDataV1,
    RecoveredStopSeedFundingDataV3,
    RecoveredHostStopCleanupAssociationDataV1, RECOVERED_HOST_STOP_CLEANUP_SEED_BYTES_V1,
    HOST_STOP_CLEANUP_ASSOCIATION_BYTES_V1};

pub(super) fn row_enrollment_v2(key: &[u8], bytes: &[u8]) -> Result<EnrollmentIdentity, ResourceBankDataError> {
    if bytes.get(8) == Some(&21) { return stop_seed::enrollment_v2(key, bytes); }
    if bytes.get(8) == Some(&22) { return cleanup_seed::enrollment_v1(key, bytes); }
    let row = RecoveredOperationFundingDataV1::decode_v1(bytes)?;
    if key != row.key_v1() { return Err(ResourceBankDataError::CorruptLedger); }
    Ok(row.enrollment)
}

pub(super) fn require_row_replayed_v2(state: &State, bytes: &[u8]) -> Result<(), ResourceBankDataError> {
    if bytes.get(8) == Some(&22) {
        RecoveredHostStopCleanupFundingDataV1::decode_v1(bytes)?.require_replayed_v1(state)
    } else if bytes.get(8) == Some(&21) {
        RecoveredLifecycleStopFundingDataV2::decode_v2(bytes)?.require_replayed_v2(state)
    } else {
        require_pair_replayed_v1(state, RecoveredOperationFundingDataV1::decode_v1(bytes)?)
    }
}

/// Validates finite cleanup, ordinary Stop or the unchanged paired grammar.
///
/// # Errors
/// Refuses mixed versions, partial/overwritten funding and unbound native cuts.
pub fn validate_recovered_funding_transaction_v2(state: &State, transaction: &JournalTransaction,
    next: u64, end: u64,
) -> Result<(), ResourceBankDataError> {
    // Historical funding remains bound to its archived invocation. A newly
    // appended row must instead name the actual current durable recipient;
    // resolving old history must never reopen that recipient's funding slot.
    for record in transaction.records() {
        if record.namespace() != RecordNamespace::ControllerResourceReservation
            || record.key().first() != Some(&PREFIX) { continue; }
        let bytes = record.value().ok_or(ResourceBankDataError::CorruptLedger)?;
        let enrollment = row_enrollment_v2(record.key(), bytes)?;
        let current = recipient::recipient_incarnation(state, enrollment)?
            .ok_or(ResourceBankDataError::CorruptLedger)?;
        if bytes[112..128] != current.recipient() {
            return Err(ResourceBankDataError::Conflict);
        }
    }
    let cleanup = transaction.records().iter().any(|record| {
        record.namespace() == RecordNamespace::ControllerResourceReservation
            && record.key().first() == Some(&PREFIX)
            && record.value().is_some_and(|bytes| bytes.get(8) == Some(&22))
    });
    if cleanup { return cleanup_seed::validate_transaction_v1(state, transaction, next, end); }
    let stop = transaction.records().iter().any(|record| {
        record.namespace() == RecordNamespace::ControllerResourceReservation
            && record.key().first() == Some(&PREFIX)
            && record.value().is_some_and(|bytes| bytes.get(8) == Some(&21))
    });
    if stop { stop_seed::validate_transaction_v2(state, transaction, next, end) }
    else { validate_recovered_funding_transaction_v1(state, transaction, next, end) }
}
