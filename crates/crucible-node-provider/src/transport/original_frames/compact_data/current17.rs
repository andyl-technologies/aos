//! Borrows every initialized field of the actual reconstructed import owner.

use super::*;
use crate::protocol_snapshot::restored_settled17::current_import17::{
    BorrowedImport17, Import17, SharedImport17, import_fields17,
};
use crate::retained_metadata::aliases::MetadataSharedKind;

import_fields17!(DecodedCompactOriginalFrames => DecodedCompactOriginalFramesCurrent17, "source-private.current-import-decoded-compact-original-frames/17", {
    bank: OriginalFrameReservation,
});

impl SharedImport17 for DecodedCompactOriginalFrames {
    const KIND: MetadataSharedKind = MetadataSharedKind::HistoricalImportFrames;
}

/// Names each concrete source, borrowed header and inert output layout.
pub(crate) fn counter_scratch_data() -> usize {
    std::mem::size_of::<DecodedCompactOriginalFrames>()
        + std::mem::size_of::<DecodedCompactOriginalFramesCurrent17>()
        + std::mem::size_of::<BorrowedImport17<'static, DecodedCompactOriginalFrames>>()
        + std::mem::size_of::<
            Result<Option<DecodedCompactOriginalFramesCurrent17>, crate::ProviderError>,
        >()
}

impl DecodedCompactOriginalFrames {
    /// Names this actual imported owner and its current17 output layout.
    pub(crate) fn current_import17_counter_scratch_data() -> usize {
        counter_scratch_data()
    }
}
