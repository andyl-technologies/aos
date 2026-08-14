//! Shared network-link test fixtures.

use super::*;
use crate::{DeviceError, PendingResponse, Response, ResponseStatus};

/// Unwraps a result in tests, panicking with the error on failure.
pub(super) fn ok<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    result.unwrap_or_else(|error| panic!("expected Ok, got {error:?}"))
}

pub(super) const SHIFT: u8 = 8; // 256 ns per icount
pub(super) const FLOOR_NS: u64 = 1_000;
pub(super) const BASE_NS: u64 = 2_560; // exactly 10 icounts at shift 8

/// Builds a fault-free link whose source id is the router slot.
pub(super) fn link(faults: LinkFaults) -> NetLink {
    let src = crucible_shmem::SLOT_NET_ROUTER as u32;
    ok(NetLink::new(SHIFT, src, BASE_NS, FLOOR_NS, faults))
}

/// A frame at emit icount 0 with a fixed 4-byte payload.
pub(super) fn frame(payload: Vec<u8>) -> Frame {
    Frame::new(0, 1, payload)
}
