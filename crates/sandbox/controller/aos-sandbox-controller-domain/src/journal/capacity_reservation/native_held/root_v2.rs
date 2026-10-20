//! Root V2 DATA framing over actual complete Protocol reducer edges.
//!
//! The original phase0 graph is borrowed historical DATA, not current-owner
//! authority. It preserves unsignedRoot1 when a legal cold Closed successor no
//! longer retains it. Current graphs are independently checked by Protocol;
//! exact original cut/scope joins never substitute historical rows for them.

use aos_sandbox_protocol::domain_ledger::capacity_family::native_held::{
    NativeHeldCapacityPurposeV3, NativeHeldCapacityRecordV3, NativeHeldCapacityRequestV3,
};

use aos_sandbox_protocol::mount_source_acquisition_state::native_held_completion::{
    RootNativeDataClassV2, RootNativeHeldGraphV2, RootNativeHeldTransitionV2,
    RootNativeNoInterestTerminalV1, RootNativeTransitionKindV2 as Kind,
    validate_native_root_transition_v2,
};
use aos_sandbox_source_provider_protocol::native_held_completion::NativeHeldControlKindV1;

use super::super::super::{
    JournalError, JournalLimits, JournalRecord, JournalTransaction, RecordNamespace,
    validate_transaction,
};
use super::super::digest_bytes;
use super::{
    NativeHeldCapacityAppendV2, NativeHeldCapacityChangeV3, NativeHeldCapacitySuffixV2, invalid,
};

pub(super) use aos_sandbox_ledger_replay::replay::native_held::root_v2::{
    RootCapacityBindingV2, RootCapacityEdgeV2,
};

pub fn root_native_capacity_admission_v2(
    proposal: &RootNativeHeldTransitionV2,
    before: &RootNativeHeldGraphV2,
    after: &RootNativeHeldGraphV2,
    mount_attempt: [u8; 32],
    transaction_id: [u8; 16],
    capacity: &NativeHeldCapacityRecordV3,
    normal: &NativeHeldCapacitySuffixV2<'_>,
    cold: &NativeHeldCapacitySuffixV2<'_>,
    limits: JournalLimits,
) -> Result<JournalTransaction, JournalError> {
    aos_sandbox_ledger_replay::replay::native_held::root_v2::root_native_capacity_admission_v2(
        proposal,
        before,
        after,
        mount_attempt,
        transaction_id,
        capacity,
        normal,
        cold,
        limits,
    )
        .map_err(JournalError::from)
}

pub fn root_native_capacity_append_v2<'graph>(
    proposal: &RootNativeHeldTransitionV2,
    before: &'graph RootNativeHeldGraphV2,
    after: &'graph RootNativeHeldGraphV2,
    original: &'graph RootNativeHeldGraphV2,
    mount_attempt: [u8; 32],
    transaction_id: [u8; 16],
) -> Result<NativeHeldCapacityAppendV2<'graph>, JournalError> {
    aos_sandbox_ledger_replay::replay::native_held::root_v2::root_native_capacity_append_v2(
        proposal,
        before,
        after,
        original,
        mount_attempt,
        transaction_id,
    )
        .map_err(JournalError::from)
}

pub fn root_native_capacity_transition_v2(
    proposal: &RootNativeHeldTransitionV2,
    before: &RootNativeHeldGraphV2,
    after: &RootNativeHeldGraphV2,
    original: &RootNativeHeldGraphV2,
    mount_attempt: [u8; 32],
    transaction_id: [u8; 16],
    old: &NativeHeldCapacityRecordV3,
    next: Option<&NativeHeldCapacityRecordV3>,
    limits: JournalLimits,
) -> Result<JournalTransaction, JournalError> {
    aos_sandbox_ledger_replay::replay::native_held::root_v2::root_native_capacity_transition_v2(
        proposal,
        before,
        after,
        original,
        mount_attempt,
        transaction_id,
        old,
        next,
        limits,
    )
        .map_err(JournalError::from)
}

fn require_retired_floor(
    marker: &RootNativeNoInterestTerminalV1,
    old: &NativeHeldCapacityRecordV3,
) -> Result<(), JournalError> {
    aos_sandbox_ledger_replay::replay::native_held::root_v2::require_retired_floor(marker, old)
        .map_err(JournalError::from)
}

fn require_proposal(
    proposal: &RootNativeHeldTransitionV2,
    before: &RootNativeHeldGraphV2,
    after: &RootNativeHeldGraphV2,
    mount_attempt: [u8; 32],
    transaction_id: [u8; 16],
) -> Result<(), JournalError> {
    aos_sandbox_ledger_replay::replay::native_held::root_v2::require_proposal(
        proposal,
        before,
        after,
        mount_attempt,
        transaction_id,
    )
        .map_err(JournalError::from)
}

fn remaining(
    graph: &RootNativeHeldGraphV2,
    attempt: [u8; 32],
    transaction_id: [u8; 16],
) -> Result<u32, JournalError> {
    aos_sandbox_ledger_replay::replay::native_held::root_v2::remaining(graph, attempt, transaction_id)
        .map_err(JournalError::from)
}

fn original_binding(
    original: &RootNativeHeldGraphV2,
    current: &RootNativeHeldGraphV2,
    attempt: [u8; 32],
) -> Result<RootCapacityBindingV2, JournalError> {
    aos_sandbox_ledger_replay::replay::native_held::root_v2::original_binding(
        original,
        current,
        attempt,
    )
        .map_err(JournalError::from)
}

fn require_floor(floor: &NativeHeldCapacityRecordV3) -> Result<(), JournalError> {
    aos_sandbox_ledger_replay::replay::native_held::root_v2::require_floor(floor)
        .map_err(JournalError::from)
}

fn proposal_records(proposal: &RootNativeHeldTransitionV2) -> Vec<JournalRecord> {
    aos_sandbox_ledger_replay::replay::native_held::root_v2::proposal_records(proposal)
}

#[cfg(test)]
use aos_sandbox_ledger_replay::replay::native_held::root_v2::fixture;

#[cfg(test)]
#[path = "../../../../../aos-sandbox-ledger-replay/src/replay/native_held/root_v2/tests.rs"]
pub(super) mod tests;
