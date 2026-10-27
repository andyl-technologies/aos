//! Shared block-device test fixtures.

use super::*;
use crate::subnode::IoCore;

/// Unwraps a result in tests, panicking with the error on failure.
pub(super) fn ok<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    result.unwrap_or_else(|error| panic!("expected Ok, got {error:?}"))
}

/// Returns a fresh heap-backed page store.
pub(super) fn mem() -> BlockPageStore {
    BlockPageStore::memory()
}

/// Streams a device's full disk image into a buffer.
pub(super) fn image(device: &BlockDevice) -> Vec<u8> {
    let mut bytes = Vec::new();
    ok(device.materialize_to(&mut bytes));
    bytes
}

/// Streams an overlay over `base` into a buffer.
pub(super) fn overlay_image(overlay: &CowOverlay, base: &BaseImage) -> Vec<u8> {
    let mut bytes = Vec::new();
    ok(overlay.materialize_to(base, &mut bytes));
    bytes
}

/// Encodes and decodes `snapshot`, binding a source holding its chunk objects.
///
/// This is the persistence path: the decoded snapshot names its overlay
/// chunks by identity only and reads them back through the bound source.
pub(super) fn encoded_round_trip(snapshot: &BlockSnapshot) -> BlockSnapshot {
    let bytes = ok(snapshot.to_canonical_bytes());
    let mut objects = std::collections::BTreeMap::new();
    let mut buffer = Vec::new();
    for chunk in ok(snapshot.overlay.chunks()) {
        if let Some(identity) = ok(snapshot.overlay.read_chunk(chunk.index, &mut buffer)) {
            objects.insert(identity, buffer.clone());
        }
    }
    let mut decoded = ok(BlockSnapshot::from_canonical_bytes(&bytes));
    decoded.bind_overlay_source(std::sync::Arc::new(objects));
    decoded
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
    let src = crucible_qemu_shmem::SLOT_BLK_IO as u32;
    let core = ok(IoCore::new(src, 16, 16));
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
        while let Some(pending) = ok(dev.core_mut().pop_response()) {
            out.push((pending.delivery_icount(), pending.response.payload));
        }
        t = lim;
    }
    out
}
