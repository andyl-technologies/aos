//! Separately named native DATA geometry for actual Root V2 and Provider shapes.
//!
//! Root edges borrow complete checked graphs and retain exact canonical adjacency;
//! Provider edges remain syntactic until the Source owner validates its sealed
//! proposal. Both profiles measure the unchanged version3 namespace46 format.

use aos_sandbox_protocol::domain_ledger::capacity_family::native_held::{
    NativeHeldCapacityPurposeV3, NativeHeldCapacityRecordV3, NativeHeldCapacityRequestV3,
};

use std::collections::BTreeSet;

use aos_sandbox_protocol::mount_source_acquisition_state::native_held_completion::{
    RootNativeDataClassV2, RootNativeTransitionKindV2,
};

use super::super::invalid;
use super::super::root_v2::RootCapacityEdgeV2;
use super::{
    JournalError, JournalLimits, JournalRecord, JournalTransaction, MeasurementAppend,
    NativeHeldCapacityChangeV3, NativeHeldCapacityGeometryV3, NativeHeldCapacityPathV3,
    NativeHeldCapacityStepV3, closed_path_shape, measure_appends, normal_successor,
    require_changes, require_owner_shape,
};

use aos_sandbox_ledger_replay::replay::native_held::profile::v2::{
    NativeHeldCapacityAppendV2, NativeHeldCapacitySuffixV2,
};

fn require_root_chain(appends: &[NativeHeldCapacityAppendV2<'_>]) -> Result<(), JournalError> {
    aos_sandbox_ledger_replay::replay::native_held::profile::v2::require_root_chain(appends)
        .map_err(JournalError::from)
}

fn require_provider_chain(
    path: NativeHeldCapacityPathV3,
    appends: &[NativeHeldCapacityAppendV2<'_>],
) -> Result<(), JournalError> {
    aos_sandbox_ledger_replay::replay::native_held::profile::v2::require_provider_chain(path, appends)
        .map_err(JournalError::from)
}

pub fn capacity_record_from_suffixes_v2(
    mut request: NativeHeldCapacityRequestV3,
    admission: [u8; 16],
    normal: &NativeHeldCapacitySuffixV2<'_>,
    closed_or_recovery: &NativeHeldCapacitySuffixV2<'_>,
    limits: JournalLimits,
) -> Result<NativeHeldCapacityRecordV3, JournalError> {
    aos_sandbox_ledger_replay::replay::native_held::profile::v2::capacity_record_from_suffixes_v2(
        request,
        admission,
        normal,
        closed_or_recovery,
        limits,
    )
    .map_err(JournalError::from)
}

pub fn provider_native_capacity_transition_v2(
    append: &NativeHeldCapacityAppendV2<'_>,
    old: &NativeHeldCapacityRecordV3,
    remaining: Option<(
        &NativeHeldCapacitySuffixV2<'_>,
        &NativeHeldCapacitySuffixV2<'_>,
    )>,
    limits: JournalLimits,
) -> Result<(JournalTransaction, Option<NativeHeldCapacityRecordV3>), JournalError> {
    aos_sandbox_ledger_replay::replay::native_held::profile::v2::provider_native_capacity_transition_v2(
        append,
        old,
        remaining,
        limits,
    )
    .map_err(JournalError::from)
}
