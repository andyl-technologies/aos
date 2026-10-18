//! Borrows every initialized field of the actual reconstructed import owner.

use super::*;
use crate::protocol_snapshot::restored_settled17::current_import17::{
    BorrowedImport17, Import17, SharedImport17, import_fields17,
};
use crate::retained_metadata::aliases::MetadataSharedKind;

import_fields17!(HistoricalNativeBootstrap => HistoricalNativeBootstrapCurrent17, "source-private.current-import-historical-native-bootstrap/17", {
    reader: super::super::super::reader::HistoricalFrameReaderFacts,
    literals: Rc<DecodedCompactOriginalFrames>,
    launch_value: Value,
    launch_bytes: Vec<u8>,
    boot_value: Value,
    boot: Rc<HistoricalNativeBoot>,
    startup: Option<super::super::startup::HistoricalNativeStartupBootstrap>,
});

/// Names each concrete source, borrowed header and inert output layout.
pub(crate) fn counter_scratch_data() -> usize {
    std::mem::size_of::<HistoricalNativeBootstrap>()
        + std::mem::size_of::<HistoricalNativeBootstrapCurrent17>()
        + std::mem::size_of::<BorrowedImport17<'static, HistoricalNativeBootstrap>>()
        + std::mem::size_of::<
            Result<Option<HistoricalNativeBootstrapCurrent17>, crate::ProviderError>,
        >()
}
