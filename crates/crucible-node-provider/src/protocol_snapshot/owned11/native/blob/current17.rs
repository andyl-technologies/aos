//! Borrows every initialized field of the actual reconstructed import owner.

use super::*;
use crate::protocol_snapshot::restored_settled17::current_import17::{
    BorrowedImport17, Import17, SharedImport17, import_fields17,
};
use crate::retained_metadata::aliases::MetadataSharedKind;

import_fields17!(HistoricalNativeBlobPin => HistoricalNativeBlobPinCurrent17, "source-private.current-import-historical-native-blob-pin/17", {
    owner: Id,
    schema: ContentRef,
    phase: HistoricalNativePinPhase,
    receipt: Option<ContentRef>,
});

import_fields17!(HistoricalNativeBlobRecord => HistoricalNativeBlobRecordCurrent17, "source-private.current-import-historical-native-blob-record/17", {
    content: ContentRef,
    length: usize,
    bytes: Vec<u8>,
    chunks: BTreeMap<usize, usize>,
    verified: bool,
    quarantined: bool,
    exposed: bool,
    retirement: Option<BlobRetirement>,
    pins: BTreeMap<u64, HistoricalNativeBlobPin>,
    charged: bool,
});

import_fields17!(HistoricalNativeBlobLedger => HistoricalNativeBlobLedgerCurrent17, "source-private.current-import-historical-native-blob-ledger/17", {
    reserved: usize,
    next_pin: U64,
    pins_created: usize,
    records: BTreeMap<TransferKey, HistoricalNativeBlobRecord>,
});

impl SharedImport17 for HistoricalNativeBlobLedger {
    const KIND: MetadataSharedKind = MetadataSharedKind::HistoricalImportBlobLedger;
}

import_fields17!(HistoricalNativeBlobReceiver => HistoricalNativeBlobReceiverCurrent17, "source-private.current-import-historical-native-blob-receiver/17", {
    session: Id,
    incarnation: Id,
    limits: BlobLimits,
    state: Rc<HistoricalNativeBlobLedger>,
    supervisor_group: usize,
});

/// Names each concrete source, borrowed header and inert output layout.
pub(crate) fn counter_scratch_data() -> usize {
    std::mem::size_of::<HistoricalNativeBlobPin>()
        + std::mem::size_of::<HistoricalNativeBlobPinCurrent17>()
        + std::mem::size_of::<BorrowedImport17<'static, HistoricalNativeBlobPin>>()
        + std::mem::size_of::<Result<Option<HistoricalNativeBlobPinCurrent17>, crate::ProviderError>>(
        )
        + std::mem::size_of::<HistoricalNativeBlobRecord>()
        + std::mem::size_of::<HistoricalNativeBlobRecordCurrent17>()
        + std::mem::size_of::<BorrowedImport17<'static, HistoricalNativeBlobRecord>>()
        + std::mem::size_of::<
            Result<Option<HistoricalNativeBlobRecordCurrent17>, crate::ProviderError>,
        >()
        + std::mem::size_of::<HistoricalNativeBlobLedger>()
        + std::mem::size_of::<HistoricalNativeBlobLedgerCurrent17>()
        + std::mem::size_of::<BorrowedImport17<'static, HistoricalNativeBlobLedger>>()
        + std::mem::size_of::<
            Result<Option<HistoricalNativeBlobLedgerCurrent17>, crate::ProviderError>,
        >()
        + std::mem::size_of::<HistoricalNativeBlobReceiver>()
        + std::mem::size_of::<HistoricalNativeBlobReceiverCurrent17>()
        + std::mem::size_of::<BorrowedImport17<'static, HistoricalNativeBlobReceiver>>()
        + std::mem::size_of::<
            Result<Option<HistoricalNativeBlobReceiverCurrent17>, crate::ProviderError>,
        >()
}
