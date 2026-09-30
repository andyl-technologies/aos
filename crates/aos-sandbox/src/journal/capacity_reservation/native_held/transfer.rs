//! Shared private framing and budget accounting for native DATA transfers.
//!
//! Owner adapters retain their binding, count and final-path validation. This
//! helper only frames an already selected exact edge and checks its full spend.

use super::super::super::{
    JournalError, JournalLimits, JournalRecord, JournalTransaction, RecordNamespace,
    encoded_transaction_append_bytes, validate_transaction,
};
use super::{NativeHeldCapacityRecordV3, NativeHeldCapacityRequestV3};

pub(super) fn frame_transfer(
    transaction_id: [u8; 16],
    mut records: Vec<JournalRecord>,
    old: &NativeHeldCapacityRecordV3,
    next: Option<&NativeHeldCapacityRecordV3>,
    limits: JournalLimits,
    errors: (&'static str, &'static str),
) -> Result<JournalTransaction, JournalError> {
    records.push(JournalRecord::delete(
        RecordNamespace::GlobalCapacityReservation,
        old.to_journal_record().key().to_vec(),
    ));
    if let Some(next) = next {
        records.push(next.to_journal_record());
    }
    let transaction = JournalTransaction::new(transaction_id, records)?;
    check_transfer(
        &transaction,
        old.request(),
        next.map(NativeHeldCapacityRecordV3::request),
        limits,
        errors,
    )?;
    Ok(transaction)
}

pub(in crate::journal) fn check_transfer(
    transaction: &JournalTransaction,
    old_request: NativeHeldCapacityRequestV3,
    next: Option<NativeHeldCapacityRequestV3>,
    limits: JournalLimits,
    errors: (&'static str, &'static str),
) -> Result<(), JournalError> {
    check_bounded_transfer(
        transaction,
        (
            old_request.terminal_records.max(old_request.poison_records),
            old_request.terminal_bytes.max(old_request.poison_bytes),
        ),
        next.map(|request| {
            (
                request.terminal_records.max(request.poison_records),
                request.terminal_bytes.max(request.poison_bytes),
            )
        }),
        limits,
        errors,
    )
}

/// Checks actual framed consumption against a family-owned remaining envelope.
///
/// # Errors
/// Rejects opened transaction limits, framing overflow or spend above the old
/// record/byte envelope after retaining the successor's remaining promise.
pub(in crate::journal) fn check_bounded_transfer(
    transaction: &JournalTransaction,
    old: (u32, u64),
    next: Option<(u32, u64)>,
    limits: JournalLimits,
    errors: (&'static str, &'static str),
) -> Result<(), JournalError> {
    validate_transaction(transaction, limits)?;

    let consumed_bytes = encoded_transaction_append_bytes(transaction)?;
    let consumed_records = u32::try_from(transaction.records().len())
        .map_err(|_| JournalError::LimitExceeded(errors.0))?;
    let (remaining_records, remaining_bytes) = next.unwrap_or((0, 0));
    let (old_records, old_bytes) = old;
    if remaining_records
        .checked_add(consumed_records)
        .is_none_or(|records| records > old_records)
        || remaining_bytes
            .checked_add(consumed_bytes)
            .is_none_or(|bytes| bytes > old_bytes)
    {
        return Err(JournalError::LimitExceeded(errors.1));
    }

    Ok(())
}
