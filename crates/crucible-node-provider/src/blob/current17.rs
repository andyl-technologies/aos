//! Borrows every initialized field of the actual reconstructed import owner.

use super::*;
use crate::protocol_snapshot::restored_settled17::current_import17::{
    BorrowedImport17, Import17, SharedImport17, import_fields17,
};
use crate::retained_metadata::aliases::MetadataSharedKind;

import_fields17!(TransferKey => TransferKeyCurrent17, "source-private.current-import-transfer-key/17", {
    origin: RequestOrigin,
    session: Id,
    incarnation: Id,
    transfer: Id,
});

import_fields17!(BlobLimits => BlobLimitsCurrent17, "source-private.current-import-blob-limits/17", {
    reserved_bytes: usize,
    content_bytes: usize,
    chunk_bytes: usize,
    transfers_per_origin: usize,
    tombstones_per_origin: usize,
    chunks_per_transfer: usize,
    operation_pins: usize,
});

/// Names each concrete source, borrowed header and inert output layout.
pub(crate) fn counter_scratch_data() -> usize {
    std::mem::size_of::<TransferKey>()
        + std::mem::size_of::<TransferKeyCurrent17>()
        + std::mem::size_of::<BorrowedImport17<'static, TransferKey>>()
        + std::mem::size_of::<Result<Option<TransferKeyCurrent17>, crate::ProviderError>>()
        + std::mem::size_of::<BlobLimits>()
        + std::mem::size_of::<BlobLimitsCurrent17>()
        + std::mem::size_of::<BorrowedImport17<'static, BlobLimits>>()
        + std::mem::size_of::<Result<Option<BlobLimitsCurrent17>, crate::ProviderError>>()
}
