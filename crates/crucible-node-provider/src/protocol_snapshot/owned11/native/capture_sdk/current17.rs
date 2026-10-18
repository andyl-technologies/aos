//! Borrows every initialized field of the actual reconstructed import owner.

use super::*;
use crate::protocol_snapshot::restored_settled17::current_import17::{
    BorrowedImport17, Import17, SharedImport17, import_fields17,
};
use crate::retained_metadata::aliases::MetadataSharedKind;

import_fields17!(HistoricalNativeCaptureSdkOwner => HistoricalNativeCaptureSdkOwnerCurrent17, "source-private.current-import-historical-native-capture-sdk-owner/17", {
    data: NativeCaptureSdkStateData,
    retained: RetainedProtocolMetadataFacts,
    strong_edges: usize,
    unique_roots: usize,
    actor_group: usize,
    codec_group: usize,
    policy: Rc<HistoricalNativePolicy>,
    frames: Rc<DecodedCompactOriginalFrames>,
});

/// Names each concrete source, borrowed header and inert output layout.
pub(crate) fn counter_scratch_data() -> usize {
    std::mem::size_of::<HistoricalNativeCaptureSdkOwner>()
        + std::mem::size_of::<HistoricalNativeCaptureSdkOwnerCurrent17>()
        + std::mem::size_of::<BorrowedImport17<'static, HistoricalNativeCaptureSdkOwner>>()
        + std::mem::size_of::<
            Result<Option<HistoricalNativeCaptureSdkOwnerCurrent17>, crate::ProviderError>,
        >()
}
