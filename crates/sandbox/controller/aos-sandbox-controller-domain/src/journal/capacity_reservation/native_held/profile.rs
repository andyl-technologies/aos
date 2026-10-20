//! Imports canonical Source suffix DATA while keeping actual writer crossings upper.

use aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1;
use super::super::super::{JournalError, JournalLimits, JournalRecord, JournalTransaction, RecordNamespace, encoded_transaction_append_bytes, validate_transaction};
use aos_sandbox_ledger_replay::replay::native_held::profile::*;
pub use aos_sandbox_ledger_replay::replay::native_held::profile::{
    NativeHeldCapacityAppendV3, NativeHeldCapacityChangeV3, NativeHeldCapacityGeometryV3,
    NativeHeldCapacityPathV3, NativeHeldCapacityStepV3, NativeHeldCapacitySuffixV3,
    NativeHeldCapacityUsageV3,
};
pub use aos_sandbox_ledger_replay::replay::native_held::profile::v2::{
    NativeHeldCapacityAppendV2, NativeHeldCapacityStepV2, NativeHeldCapacitySuffixV2,
};
mod v2;
pub(in crate::journal::capacity_reservation::native_held) use v2::capacity_record_from_suffixes_v2;
