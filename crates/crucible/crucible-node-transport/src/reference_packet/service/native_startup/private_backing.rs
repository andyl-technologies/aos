//! Supplies actual compiled primitive layouts for the private bootstrap banks.
//!
//! This const-only DATA source names OsString and the genuine frame reservation
//! payload. Shared-header arithmetic remains the defining lower implementation;
//! no Rc layout mirror, native owner, capability or final row is supplied.

use crate::ProviderError;
use crate::transport::original_frames::OriginalFrameReservation;
pub(super) use crucible_source_birth_data::profile::reference_packet::service::native_startup::private_backing as shared;
use std::cell::RefCell;
use std::mem::{align_of, size_of};

pub(super) const LAYOUT_DATA: shared::PrivateBackingLayoutData = shared::PrivateBackingLayoutData {
    os_string_bytes: size_of::<std::ffi::OsString>(),
    frame_reservation_bytes: size_of::<RefCell<OriginalFrameReservation>>(),
    frame_reservation_alignment: align_of::<RefCell<OriginalFrameReservation>>(),
};

// Only the new forwarding boundaries are added here. The old shared-header
// implementation/control families remain independently owned by their caller.
// Const field selection runs no runtime layout observer or header constructor.
pub(super) const ADAPTER_COUNTER_SCRATCH_DATA: usize = 4 * size_of::<usize>() // formed shared-bank scalar operands and callee inputs
        + size_of::<Result<usize, ProviderError>>() // lower shared-bank return
        + 4 * size_of::<usize>() // invocation wrapper/helper scalar operands and inputs
        + 2 * size_of::<bool>() // actual cfg predicate and private helper input
        + 2 * size_of::<Result<usize, ProviderError>>(); // helper and public lower returns

#[cfg(test)]
mod tests;
