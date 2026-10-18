//! Borrows every initialized field of the actual reconstructed import owner.

use super::*;
use crate::protocol_snapshot::restored_settled17::current_import17::{
    BorrowedImport17, Import17, SharedImport17, import_fields17,
};
use crate::retained_metadata::aliases::MetadataSharedKind;

import_fields17!(ConnectionIncident => ConnectionIncidentCurrent17, "source-private.current-import-connection-incident/17", {
    session: Id,
    incarnation: Id,
    connection: Id,
    failure: ConnectionFailure,
    transport_fenced: bool,
    outgoing: Vec<Envelope>,
    incoming: Vec<Envelope>,
});

/// Names each concrete source, borrowed header and inert output layout.
pub(crate) fn counter_scratch_data() -> usize {
    std::mem::size_of::<ConnectionIncident>()
        + std::mem::size_of::<ConnectionIncidentCurrent17>()
        + std::mem::size_of::<BorrowedImport17<'static, ConnectionIncident>>()
        + std::mem::size_of::<Result<Option<ConnectionIncidentCurrent17>, crate::ProviderError>>()
}
