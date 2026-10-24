//! Borrows every sealed suffix construction axis and launch identity as DATA.
//!
//! ```text
//! {native_retained,native_transient,private_retained,private_transient,
//!  source_finalization,wire_growth,identity:[encoded_bytes,raw_digest]}
//! ```

use super::*;
use crate::protocol_snapshot::compact_bytes::BorrowedCompactBytes;
use serde::{Serialize, Serializer, ser::SerializeStruct};

struct History<'a>(&'a PacketNativeSuffixConstructionStorageData);

impl PacketNativeSuffixConstructionStorageData {
    /// Borrows the complete fixed quote without recreating a startup member.
    pub fn borrowed_settled17_history_data(&self) -> impl Serialize + '_ {
        History(self)
    }

    /// Counts this fixed borrowed quote, identity and byte serializer views.
    pub fn settled17_history_counter_scratch_data() -> usize {
        size_of::<History<'static>>()
            + size_of::<[&usize; 7]>()
            + size_of::<BorrowedCompactBytes<'static>>()
            + BorrowedCompactBytes::requested_serialization_scratch_bytes()
    }
}

impl Serialize for History<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let PacketNativeSuffixConstructionStorageData {
            native_retained,
            native_transient,
            private_retained,
            private_transient,
            source_finalization,
            wire_growth,
            identity,
        } = self.0;
        let PacketNativeSuffixLaunchIdentityData {
            encoded_bytes,
            raw_digest,
        } = identity;
        let mut state = serializer.serialize_struct("HistoricalSuffixConstruction17", 7)?;
        state.serialize_field("native_retained", native_retained)?;
        state.serialize_field("native_transient", native_transient)?;
        state.serialize_field("private_retained", private_retained)?;
        state.serialize_field("private_transient", private_transient)?;
        state.serialize_field("source_finalization", source_finalization)?;
        state.serialize_field("wire_growth", wire_growth)?;
        state.serialize_field(
            "identity",
            &(encoded_bytes, BorrowedCompactBytes::new(raw_digest)),
        )?;
        state.end()
    }
}
