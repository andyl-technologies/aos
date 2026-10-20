//! Owns Native suffix geometry, purpose builders and graph-rederiving adapters.
//!
//! Canonical capacity records and their sole codecs live in Protocol's
//! `domain_ledger::capacity_family`. These upper adapters measure exact owner
//! continuations; actual protected Journal admission and custody stay Native.

use super::super::JournalError;
#[cfg(test)]
use super::super::{JournalRecord, RecordNamespace};

mod profile;
mod root;
mod root_v2;

#[cfg(test)]
pub(in crate::journal) use aos_sandbox_ledger_replay::replay::native_held::root_v2::fixture::Original as NativeRootDataFixture;
mod transfer;
pub(in crate::journal) use transfer::{check_bounded_transfer, check_transfer};

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


fn invalid(reason: &'static str) -> JournalError {
    aos_sandbox_ledger_replay::replay::native_held::invalid(reason).into()
}

#[cfg(test)]
mod tests;
