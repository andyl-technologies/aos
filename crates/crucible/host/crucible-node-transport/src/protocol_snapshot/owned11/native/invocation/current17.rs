//! Borrows every initialized field of the actual reconstructed import owner.

use super::*;
use crate::protocol_snapshot::restored_settled17::current_import17::{
    BorrowedImport17, import_fields17,
};

import_fields17!(HistoricalNativeInvocationPhase => HistoricalNativeInvocationPhaseCurrent17, "source-private.current-import-historical-native-invocation-phase/17", {
    birth_id: [u8; 32],
});

/// Names each concrete source, borrowed header and inert output layout.
pub(crate) fn counter_scratch_data() -> usize {
    std::mem::size_of::<HistoricalNativeInvocationPhase>()
        + std::mem::size_of::<HistoricalNativeInvocationPhaseCurrent17>()
        + std::mem::size_of::<BorrowedImport17<'static, HistoricalNativeInvocationPhase>>()
        + std::mem::size_of::<
            Result<Option<HistoricalNativeInvocationPhaseCurrent17>, crate::ProviderError>,
        >()
}
