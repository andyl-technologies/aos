//! Borrows every initialized field of the actual reconstructed import owner.

use super::*;
use crate::protocol_snapshot::restored_settled17::current_import17::{
    BorrowedImport17, import_fields17,
};

import_fields17!(HistoricalAuthority => HistoricalAuthorityCurrent17, "source-private.current-import-historical-authority/17", {
    connection: Id,
    session: Id,
    incarnation: Id,
    epoch: U64,
    limits: Limits,
    features: IdSet,
    envelope_extensions: BTreeSet<String>,
    extensions: Option<std::sync::Arc<[ExtensionSelection]>>,
});

import_fields17!(HistoricalCorrelations => HistoricalCorrelationsCurrent17, "source-private.current-import-historical-correlations/17", {
    session: Id,
    incarnation: Id,
    next_received: U64,
    next_sent: U64,
    maximum_requests: usize,
    pending: BTreeMap<Id, Envelope>,
    received_requests: BTreeMap<Id, Envelope>,
    writing_responses: BTreeMap<Id, Envelope>,
    extensions: BTreeSet<String>,
    failed: bool,
    continuation_installed: bool,
});

/// Names each concrete source, borrowed header and inert output layout.
pub(crate) fn counter_scratch_data() -> usize {
    std::mem::size_of::<HistoricalAuthority>()
        + std::mem::size_of::<HistoricalAuthorityCurrent17>()
        + std::mem::size_of::<BorrowedImport17<'static, HistoricalAuthority>>()
        + std::mem::size_of::<Result<Option<HistoricalAuthorityCurrent17>, crate::ProviderError>>()
        + std::mem::size_of::<HistoricalCorrelations>()
        + std::mem::size_of::<HistoricalCorrelationsCurrent17>()
        + std::mem::size_of::<BorrowedImport17<'static, HistoricalCorrelations>>()
        + std::mem::size_of::<Result<Option<HistoricalCorrelationsCurrent17>, crate::ProviderError>>(
        )
}
