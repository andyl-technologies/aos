//! Shared block-device test fixtures.

use super::*;
use crate::subnode::IoCore;

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

/// Drives a fixed request sequence under artificial host-side compute skew.
pub(super) fn run_sequence(skew: usize) -> Vec<(u64, Vec<u8>)> {
    let mut dev = device(PAGE_SIZE * 4);
    let reqs = [
        BlockRequest::read(1, 0, 16),
        BlockRequest::write(2, 100, vec![0x33; 32]),
        BlockRequest::read(3, 100, 32),
        BlockRequest::flush(4),
        BlockRequest::get_length(5),
    ];
    let mut out = Vec::new();
    let mut t = 0_u64;
    for req in &reqs {
        let mut sink = 0_u64;
        for i in 0..skew {
            sink = sink.wrapping_add(i as u64);
        }
        std::hint::black_box(sink);

        ok(dev.submit(t, req));
        let lim = dev.core().next_exact_local_event().unwrap_or(t);
        ok(dev.advance_to(lim));
        while let Some(pending) = dev.core_mut().pop_response() {
            out.push((pending.delivery_icount(), pending.response.payload));
        }
        t = lim;
    }
    out
}
