//! Typed resource-error propagation for nested host-I/O checkpoints.

use super::*;

pub(super) fn map_host_ring_error(
    error: SpscRingError,
    field: &'static str,
    configured_frames: u32,
) -> QemuHostIoCheckpointCodecError {
    match error {
        SpscRingError::SnapshotAllocationFailed { count }
        | SpscRingError::SnapshotTooLarge { len: count, .. } => {
            QemuHostIoCheckpointCodecError::ResourceLimit {
                field,
                current: 0,
                requested: count as u64,
                configured: u64::from(configured_frames),
                hard: 1_048_576,
            }
        }
        SpscRingError::SnapshotFrameCountOverflow { count } => {
            QemuHostIoCheckpointCodecError::ResourceLimit {
                field,
                current: 0,
                requested: count,
                configured: u64::from(configured_frames),
                hard: 1_048_576,
            }
        }
        SpscRingError::SnapshotPayloadAllocationFailed { len } => {
            QemuHostIoCheckpointCodecError::ResourceLimit {
                field,
                current: 0,
                requested: len as u64,
                configured: crucible_shmem::MAX_FRAME_DATA as u64,
                hard: crucible_shmem::MAX_FRAME_DATA as u64,
            }
        }
        SpscRingError::SnapshotByteAllocationFailed { len }
        | SpscRingError::SnapshotLengthOverflow { len } => {
            QemuHostIoCheckpointCodecError::ResourceLimit {
                field,
                current: 0,
                requested: len as u64,
                configured: MAX_BYTES,
                hard: MAX_BYTES,
            }
        }
        _ => QemuHostIoCheckpointCodecError::Nested,
    }
}

pub(super) fn map_block_snapshot_error(
    error: BlockSnapshotCodecError,
) -> QemuHostIoCheckpointCodecError {
    match error {
        BlockSnapshotCodecError::ResourceLimit {
            field,
            current,
            requested,
            configured,
            hard,
        } => QemuHostIoCheckpointCodecError::ResourceLimit {
            field,
            current,
            requested,
            configured,
            hard,
        },
        _ => QemuHostIoCheckpointCodecError::Nested,
    }
}

pub(super) fn map_ninep_snapshot_error(
    error: NinepSnapshotCodecError,
) -> QemuHostIoCheckpointCodecError {
    match error {
        NinepSnapshotCodecError::ResourceLimit {
            field,
            current,
            requested,
            configured,
            hard,
        } => QemuHostIoCheckpointCodecError::ResourceLimit {
            field,
            current,
            requested,
            configured,
            hard,
        },
        _ => QemuHostIoCheckpointCodecError::Nested,
    }
}

pub(super) fn map_bounded_cbor_error(error: BoundedCborError) -> QemuHostIoCheckpointCodecError {
    match error {
        BoundedCborError::Malformed => QemuHostIoCheckpointCodecError::Malformed,
        BoundedCborError::ResourceLimit {
            field,
            current,
            requested,
            configured,
            hard,
        } => QemuHostIoCheckpointCodecError::ResourceLimit {
            field,
            current,
            requested,
            configured,
            hard,
        },
    }
}

pub(super) fn bounded_bytes(
    bytes: Vec<u8>,
) -> Result<BoundedVec<u8, HARD_FAT_CHECKPOINT_BYTES>, QemuHostIoCheckpointCodecError> {
    BoundedVec::new(bytes).map_err(map_bounded_cbor_error)
}
