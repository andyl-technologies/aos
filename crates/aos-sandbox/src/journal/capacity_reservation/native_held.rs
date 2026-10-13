//! Owns Native suffix geometry, purpose builders and graph-rederiving adapters.
//!
//! Canonical capacity records and their sole codecs live in Protocol's
//! `domain_ledger::capacity_family`. These upper adapters measure exact owner
//! continuations; actual protected Journal admission and custody stay Native.

use aos_sandbox_protocol::domain_ledger::capacity_family::native_held::{NativeHeldCapacityRecordV3, NativeHeldCapacityRequestV3};

use super::super::{JournalError, JournalRecord, RecordNamespace};

mod admission;
mod profile;
mod root;
mod root_v2;

#[cfg(test)]
pub(in crate::journal) use root_v2::tests::Original as NativeRootDataFixture;
mod transfer;
pub(in crate::journal) use transfer::{check_bounded_transfer, check_transfer};

pub use admission::{
    NativeHeldProviderAdmissionDataV3, provider_native_capacity_admission_v3,
    provider_native_capacity_transition_v3,
};
pub use profile::provider_native_capacity_transition_v2;
pub(in crate::journal) use profile::{
    OriginalSourceGeometryDataV5, OriginalSourceMeasuredAlternativeV5,
    check_original_source_candidate_spend_v5, derive_original_source_geometry_v5,
};
pub use profile::{
    NativeHeldCapacityAppendV2, NativeHeldCapacityAppendV3, NativeHeldCapacityChangeV3,
    NativeHeldCapacityGeometryV3, NativeHeldCapacityPathV3, NativeHeldCapacityStepV2,
    NativeHeldCapacityStepV3, NativeHeldCapacitySuffixV2, NativeHeldCapacitySuffixV3,
    NativeHeldCapacityUsageV3,
};
pub use root::{
    root_native_capacity_admission_v3, root_native_capacity_append_v3,
    root_native_capacity_transition_v3,
};
pub use root_v2::{
    root_native_capacity_admission_v2, root_native_capacity_append_v2,
    root_native_capacity_transition_v2,
};

/// Derives complete native budgets from both measured legal continuations.
///
/// The input request supplies immutable DATA bindings only; its count and
/// record/byte budgets are replaced by measurements of exact owner proposal
/// bytes. The original owner must independently validate every proposal and
/// any excluded branch before using this data at a future effect boundary.
///
/// # Errors
///
/// Rejects a foreign owner, wrong continuation classes, invalid bindings,
/// malformed suffix, or any unchanged journal ceiling violation.
pub fn capacity_record_from_suffixes_v3(
    mut request: NativeHeldCapacityRequestV3,
    admission: [u8; 16],
    normal: &NativeHeldCapacitySuffixV3,
    closed_or_recovery: &NativeHeldCapacitySuffixV3,
    limits: super::super::JournalLimits,
) -> Result<NativeHeldCapacityRecordV3, JournalError> {
    if normal.purpose() != request.purpose
        || closed_or_recovery.purpose() != request.purpose
        || normal.path() != NativeHeldCapacityPathV3::Normal
        || closed_or_recovery.path() == NativeHeldCapacityPathV3::Normal
    {
        return Err(invalid("native capacity owner or continuation classes"));
    }
    let terminal = normal.measure(limits)?;
    let poison = closed_or_recovery.measure(limits)?;
    request.future_transactions = terminal.transactions.max(poison.transactions);
    request.terminal_records = terminal.records;
    request.terminal_bytes = terminal.append_bytes;
    request.poison_records = poison.records;
    request.poison_bytes = poison.append_bytes;
    NativeHeldCapacityRecordV3::new(request, admission).map_err(JournalError::from)
}

fn invalid(reason: &'static str) -> JournalError {
    JournalError::MalformedRecord(reason)
}

#[cfg(test)]
mod tests;
