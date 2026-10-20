//! Retains Source's opened headroom checks beside its actual held writer.
//!
//! Canonical suffixes and transfer measurements remain in LedgerReplay. These
//! Source adapters join them to the held provider graph and physical journal;
//! their comparison DATA cannot create an original authority or signing basis.

use aos_sandbox_protocol::domain_ledger::capacity_family::native_held::{
    NativeHeldCapacityRecordV3, NativeHeldCapacityRequestV3,
};

use super::{JournalError, JournalLimits};

mod admission;
mod original_geometry;

pub use admission::{
    NativeHeldProviderAdmissionDataV3, provider_native_capacity_admission_v3,
    provider_native_capacity_transition_v3,
};
pub(super) use aos_sandbox_ledger_replay::replay::native_held::profile::original_source::{
    OriginalSourceGeometryDataV5, OriginalSourceMeasuredAlternativeV5,
};
pub use aos_sandbox_ledger_replay::replay::native_held::profile::v2::{
    NativeHeldCapacityAppendV2, NativeHeldCapacityStepV2, NativeHeldCapacitySuffixV2,
    provider_native_capacity_transition_v2,
};
pub use aos_sandbox_ledger_replay::replay::native_held::profile::{
    NativeHeldCapacityAppendV3, NativeHeldCapacityChangeV3, NativeHeldCapacityGeometryV3,
    NativeHeldCapacityPathV3, NativeHeldCapacityStepV3, NativeHeldCapacitySuffixV3,
    NativeHeldCapacityUsageV3,
};
pub(super) use original_geometry::{
    check_original_source_candidate_spend_v5, derive_original_source_geometry_v5,
};

use aos_sandbox_ledger_replay::replay::native_held::profile::add;

/// Measures both exact continuations without granting their future appends.
///
/// The actual Source original separately validates the complete owner graph
/// and its remaining physical headroom before relying on this comparison.
///
/// # Errors
///
/// Rejects a foreign purpose, changed continuation class, invalid exact suffix,
/// checked-arithmetic overflow, or an unchanged journal ceiling violation.
pub fn capacity_record_from_suffixes_v3(
    mut request: NativeHeldCapacityRequestV3,
    admission: [u8; 16],
    normal: &NativeHeldCapacitySuffixV3,
    closed_or_recovery: &NativeHeldCapacitySuffixV3,
    limits: JournalLimits,
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
    aos_sandbox_ledger_replay::replay::native_held::invalid(reason)
}
