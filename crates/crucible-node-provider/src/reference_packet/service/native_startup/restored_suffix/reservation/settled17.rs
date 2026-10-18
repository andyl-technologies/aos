//! Lends the exhaustive existing sealed suffix quote to the host historical writer.

use super::*;
use serde::Serialize;

impl PacketNativeRestoredSuffixStartupStorageData {
    /// Borrows every sealed quote field without constructing a reservation grant.
    pub fn borrowed_settled17_history_data(&self) -> impl Serialize + '_ {
        self.borrowed_settled_history_data()
    }

    /// Counts the defining fixed quote serializer and compact digest views.
    pub fn settled17_history_counter_scratch_data() -> usize {
        Self::settled_history_counter_scratch_data()
            + std::mem::size_of::<crate::protocol_snapshot::compact_bytes::BorrowedCompactBytes<'static>>()
            + crate::protocol_snapshot::compact_bytes::BorrowedCompactBytes::requested_serialization_scratch_bytes()
    }
}
