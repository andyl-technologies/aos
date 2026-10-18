//! Borrows every initialized field of the actual reconstructed import owner.

use super::*;
use crate::protocol_snapshot::restored_settled17::current_import17::{
    BorrowedImport17, Import17, SharedImport17, import_fields17,
};
use crate::retained_metadata::aliases::MetadataSharedKind;

import_fields17!(HistoricalNativeCaptureCurrency => HistoricalNativeCaptureCurrencyCurrent17, "source-private.current-import-historical-native-capture-currency/17", {
    creator: u32,
    originals_before: usize,
    cursor: Position,
    control_group: usize,
});

import_fields17!(HistoricalNativeCaptureAllocationOwner => HistoricalNativeCaptureAllocationOwnerCurrent17, "source-private.current-import-historical-native-capture-allocation-owner/17", {
    creator: u32,
    observe: Envelope,
    sdk: HistoricalNativeCaptureSdkOwner,
    currency: HistoricalNativeCaptureCurrency,
    report: PacketNativeCaptureAllocationReport,
    report_reference: ContentRef,
    encoded_report: Vec<u8>,
    capture: Option<Envelope>,
});

/// Names each concrete source, borrowed header and inert output layout.
pub(crate) fn counter_scratch_data() -> usize {
    std::mem::size_of::<HistoricalNativeCaptureCurrency>()
        + std::mem::size_of::<HistoricalNativeCaptureCurrencyCurrent17>()
        + std::mem::size_of::<BorrowedImport17<'static, HistoricalNativeCaptureCurrency>>()
        + std::mem::size_of::<
            Result<Option<HistoricalNativeCaptureCurrencyCurrent17>, crate::ProviderError>,
        >()
        + std::mem::size_of::<HistoricalNativeCaptureAllocationOwner>()
        + std::mem::size_of::<HistoricalNativeCaptureAllocationOwnerCurrent17>()
        + std::mem::size_of::<BorrowedImport17<'static, HistoricalNativeCaptureAllocationOwner>>()
        + std::mem::size_of::<
            Result<Option<HistoricalNativeCaptureAllocationOwnerCurrent17>, crate::ProviderError>,
        >()
}
