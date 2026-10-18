//! Borrows every initialized field of the actual reconstructed import owner.

use super::*;
use crate::protocol_snapshot::restored_settled17::current_import17::{
    BorrowedImport17, import_fields17,
};

import_fields17!(HistoricalNativeConnection => HistoricalNativeConnectionCurrent17, "source-private.current-import-historical-native-connection/17", {
    actor_group: usize,
    authority: HistoricalAuthority,
    correlations: HistoricalCorrelations,
    codec_group: usize,
    policy: Rc<HistoricalNativePolicy>,
    frames: Rc<DecodedCompactOriginalFrames>,
    reader: HistoricalFrameReaderFacts,
    blob_ledger: Rc<super::super::blob::HistoricalNativeBlobLedger>,
    supervisor_group: usize,
    packet_schema: bool,
    connected_packet_schema: bool,
    fenced: bool,
    admission: HistoricalNativeAckToken,
});

/// Names each concrete source, borrowed header and inert output layout.
pub(crate) fn counter_scratch_data() -> usize {
    std::mem::size_of::<HistoricalNativeConnection>()
        + std::mem::size_of::<HistoricalNativeConnectionCurrent17>()
        + std::mem::size_of::<BorrowedImport17<'static, HistoricalNativeConnection>>()
        + std::mem::size_of::<
            Result<Option<HistoricalNativeConnectionCurrent17>, crate::ProviderError>,
        >()
}
