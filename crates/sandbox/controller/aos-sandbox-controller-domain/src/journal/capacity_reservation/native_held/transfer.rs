//! Shared private framing and budget accounting for native DATA transfers.
//!
//! Owner adapters retain their binding, count and final-path validation. This
//! helper only frames an already selected exact edge and checks its full spend.

use aos_sandbox_protocol::domain_ledger::capacity_family::native_held::{
    NativeHeldCapacityRecordV3, NativeHeldCapacityRequestV3,
};

use super::super::super::{
    JournalError, JournalLimits, JournalRecord, JournalTransaction, RecordNamespace,
    encoded_transaction_append_bytes, validate_transaction,
};

pub(super) fn frame_transfer(
    transaction_id: [u8; 16],
    mut records: Vec<JournalRecord>,
    old: &NativeHeldCapacityRecordV3,
    next: Option<&NativeHeldCapacityRecordV3>,
    limits: JournalLimits,
    errors: (&'static str, &'static str),
) -> Result<JournalTransaction, JournalError> {
    aos_sandbox_ledger_replay::replay::native_transfer::frame_transfer(
        transaction_id,
        records,
        old,
        next,
        limits,
        errors,
    )
        .map_err(JournalError::from)
}

pub(in crate::journal) fn check_transfer(
    transaction: &JournalTransaction,
    old_request: NativeHeldCapacityRequestV3,
    next: Option<NativeHeldCapacityRequestV3>,
    limits: JournalLimits,
    errors: (&'static str, &'static str),
) -> Result<(), JournalError> {
    aos_sandbox_ledger_replay::replay::native_transfer::check_transfer(
        transaction,
        old_request,
        next,
        limits,
        errors,
    )
        .map_err(JournalError::from)
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
    aos_sandbox_ledger_replay::replay::native_transfer::check_bounded_transfer(
        transaction,
        old,
        next,
        limits,
        errors,
    )
        .map_err(JournalError::from)
}
