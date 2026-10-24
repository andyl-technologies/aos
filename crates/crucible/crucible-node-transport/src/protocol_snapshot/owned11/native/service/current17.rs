//! Borrows every initialized field of the actual reconstructed import owner.

use super::*;
use crate::protocol_snapshot::restored_settled17::current_import17::{
    BorrowedImport17, import_fields17,
};

import_fields17!(HistoricalNativeService => HistoricalNativeServiceCurrent17, "source-private.current-import-historical-native-service/17", {
    negotiation: HistoricalNativeExtensionNegotiation,
    bootstrap: HistoricalNativeBootstrap,
    supervisor_group: usize,
    supervisor_banks: crate::reference_packet::service::HistoricalNativeSupervisorBanks,
    endpoint_boot: Rc<HistoricalNativeBoot>,
    endpoint_policy: Rc<HistoricalNativePolicy>,
    deadline_group: usize,
});

/// Names each concrete source, borrowed header and inert output layout.
pub(crate) fn counter_scratch_data() -> usize {
    std::mem::size_of::<HistoricalNativeService>()
        + std::mem::size_of::<HistoricalNativeServiceCurrent17>()
        + std::mem::size_of::<BorrowedImport17<'static, HistoricalNativeService>>()
        + std::mem::size_of::<Result<Option<HistoricalNativeServiceCurrent17>, crate::ProviderError>>(
        )
}
