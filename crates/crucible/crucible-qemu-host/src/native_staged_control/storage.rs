//! Checked preallocation geometry for the original finite socket actor.

use super::{Custody, Exchange, InitialIoJournal, NativeWholeControlError, StageHistory};
use crucible_qemu_protocol::whole_control::{
    WHOLE_FRAME_HEADER_BYTES,
    staged::{STAGE_RECEIPT_BYTES, StagedControlProfile},
};

pub(super) fn required_bytes(
    profile: &StagedControlProfile,
    initial_protocol: bool,
) -> Result<usize, NativeWholeControlError> {
    let compute_extent = WHOLE_FRAME_HEADER_BYTES + profile.compute.body_byte_limit as usize;
    let stage_extent = WHOLE_FRAME_HEADER_BYTES + profile.stage_body_byte_limit as usize;
    let record_capacity = profile.stage_body_byte_limit as usize / 216;
    let stage_bytes = stage_extent
        .checked_add(WHOLE_FRAME_HEADER_BYTES + STAGE_RECEIPT_BYTES)
        .and_then(|size| size.checked_add(std::mem::size_of::<StageHistory>()))
        .and_then(|size| size.checked_add(record_capacity))
        .and_then(|size| size.checked_mul(profile.input_stage_limit as usize));
    let total = compute_extent
        .checked_mul(2)
        .and_then(|size| size.checked_add(std::mem::size_of::<Exchange>()))
        .and_then(|size| size.checked_mul(profile.compute.operation_capacity as usize))
        .and_then(|size| stage_bytes.and_then(|stages| size.checked_add(stages)))
        .and_then(|size| size.checked_add(stage_extent.max(compute_extent)))
        .and_then(|size| size.checked_add(compute_extent + std::mem::size_of::<Exchange>()))
        .and_then(|size| size.checked_add(compute_extent + std::mem::size_of::<Exchange>()))
        .and_then(|size| size.checked_add(std::mem::size_of::<Custody>()));
    let total = if initial_protocol {
        total.and_then(|size| {
            InitialIoJournal::required_bytes(profile).and_then(|initial| size.checked_add(initial))
        })
    } else {
        total
    };

    total.ok_or(NativeWholeControlError::Allocation)
}
