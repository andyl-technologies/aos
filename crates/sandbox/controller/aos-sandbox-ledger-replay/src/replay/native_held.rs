//! Measures complete saved native suffix DATA without a writer or capacity grant.

use super::{JournalError, JournalLimits, JournalRecord, JournalTransaction, RecordNamespace, validate_transaction};
use super::native_transfer as transfer;
use aos_sandbox_protocol::domain_ledger::capacity_family::native_held::{NativeHeldCapacityRecordV3, NativeHeldCapacityRequestV3};
#[cfg(test)]
use super::native_transfer::check_transfer;

/// Owns the canonical exact suffix models and measurement engine.
pub mod profile;
/// Frames exact historical Root version-two DATA edges.
pub mod root_v2;
pub use profile::{
    NativeHeldCapacityAppendV2, NativeHeldCapacityAppendV3, NativeHeldCapacityChangeV3,
    NativeHeldCapacityGeometryV3, NativeHeldCapacityPathV3, NativeHeldCapacityStepV2,
    NativeHeldCapacityStepV3, NativeHeldCapacitySuffixV2, NativeHeldCapacitySuffixV3,
    NativeHeldCapacityUsageV3,
};

/// Returns the unchanged invalid measurement classification.
#[doc(hidden)]
pub fn invalid(reason: &'static str) -> JournalError {
    JournalError::MalformedRecord(reason)
}
