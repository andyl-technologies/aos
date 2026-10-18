//! Borrows every initialized field of the actual reconstructed import owner.

use super::*;
use crate::protocol_snapshot::restored_settled17::current_import17::{
    BorrowedImport17, Import17, SharedImport17, import_fields17,
};
use crate::retained_metadata::aliases::MetadataSharedKind;

import_fields17!(Slot => SlotCurrent17, "source-private.current-import-slot/17", {
    direction: FrameDirection,
    start: usize,
    length: usize,
    transferred: usize,
    complete: bool,
    request: Option<([u8; 128], usize)>,
});

import_fields17!(OriginalFrameReservation => OriginalFrameReservationCurrent17, "source-private.current-import-original-frame-reservation/17", {
    bytes: Vec<u8>,
    slots: Vec<Slot>,
    maximum_bytes: usize,
    maximum_frames: usize,
    incoming: usize,
    outgoing: usize,
});

/// Names each concrete source, borrowed header and inert output layout.
pub(crate) fn counter_scratch_data() -> usize {
    std::mem::size_of::<Slot>()
        + std::mem::size_of::<SlotCurrent17>()
        + std::mem::size_of::<BorrowedImport17<'static, Slot>>()
        + std::mem::size_of::<Result<Option<SlotCurrent17>, crate::ProviderError>>()
        + std::mem::size_of::<OriginalFrameReservation>()
        + std::mem::size_of::<OriginalFrameReservationCurrent17>()
        + std::mem::size_of::<BorrowedImport17<'static, OriginalFrameReservation>>()
        + std::mem::size_of::<Result<Option<OriginalFrameReservationCurrent17>, crate::ProviderError>>(
        )
}
