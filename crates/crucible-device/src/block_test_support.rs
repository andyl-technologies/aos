//! Shared block-device test fixtures.

use super::*;
use crate::DeviceError;
use crate::subnode::IoCore;
use crucible_shmem::{FrameEntry, KIND_VM, NodeSlot, RingHeader};

/// Unwraps a result in tests, panicking with the error on failure.
pub(super) fn ok<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    result.unwrap_or_else(|error| panic!("expected Ok, got {error:?}"))
}

/// Builds a base image of `len` bytes filled with a deterministic ramp.
pub(super) fn ramp_base(len: usize) -> BaseImage {
    let bytes: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
    BaseImage::new(bytes)
}

/// Builds a block device over a ramp base with default latency.
///
/// The source-node id is the reserved `SLOT_BLK_IO` slot index so the
/// delivery keys match the shmem transport's tie-break order.
pub(super) fn device(base_len: usize) -> BlockDevice {
    device_with_latency(base_len, BlockLatency::default())
}

/// Builds a block device over a ramp base with an explicit latency model.
pub(super) fn device_with_latency(base_len: usize, latency: BlockLatency) -> BlockDevice {
    let src = crucible_shmem::SLOT_BLK_IO as u32;
    let core = ok(IoCore::new(8, src, 16, 16));
    BlockDevice::new(core, ramp_base(base_len), latency)
}
