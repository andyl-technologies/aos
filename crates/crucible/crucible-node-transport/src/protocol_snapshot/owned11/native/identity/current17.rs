//! Borrows every initialized field of the actual reconstructed import owner.

use super::*;
use crate::protocol_snapshot::restored_settled17::current_import17::{
    BorrowedImport17, import_fields17,
};

import_fields17!(HistoricalNativeAckIdentity => HistoricalNativeAckIdentityCurrent17, "source-private.current-import-historical-native-ack-identity/17", {
    actor_group: usize,
    authority: HistoricalAuthority,
    policy: Rc<HistoricalNativePolicy>,
    frames: Rc<DecodedCompactOriginalFrames>,
    admit_id: Id,
    admit_sequence: U64,
    literal_index: usize,
    literal_length: usize,
    literal_digest: [u8; 32],
});

/// Names each concrete source, borrowed header and inert output layout.
pub(crate) fn counter_scratch_data() -> usize {
    std::mem::size_of::<HistoricalNativeAckIdentity>()
        + std::mem::size_of::<HistoricalNativeAckIdentityCurrent17>()
        + std::mem::size_of::<BorrowedImport17<'static, HistoricalNativeAckIdentity>>()
        + std::mem::size_of::<
            Result<Option<HistoricalNativeAckIdentityCurrent17>, crate::ProviderError>,
        >()
}
