//! Borrows every initialized field of the actual reconstructed import owner.

use super::*;
use crate::protocol_snapshot::restored_settled17::current_import17::{
    BorrowedImport17, Import17, SharedImport17, import_fields17,
};
use crate::retained_metadata::aliases::MetadataSharedKind;

import_fields17!(HistoricalNativeAckToken => HistoricalNativeAckTokenCurrent17, "source-private.current-import-historical-native-ack-token/17", {
    identity: HistoricalNativeAckIdentity,
    boot: Rc<HistoricalNativeBoot>,
    policy: Rc<HistoricalNativePolicy>,
    authority: HistoricalAuthority,
    original: Envelope,
});

/// Names each concrete source, borrowed header and inert output layout.
pub(crate) fn counter_scratch_data() -> usize {
    std::mem::size_of::<HistoricalNativeAckToken>()
        + std::mem::size_of::<HistoricalNativeAckTokenCurrent17>()
        + std::mem::size_of::<BorrowedImport17<'static, HistoricalNativeAckToken>>()
        + std::mem::size_of::<Result<Option<HistoricalNativeAckTokenCurrent17>, crate::ProviderError>>(
        )
}
