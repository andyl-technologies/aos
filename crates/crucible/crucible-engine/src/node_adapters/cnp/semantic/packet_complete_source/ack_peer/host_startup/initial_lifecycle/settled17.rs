//! Borrows all sealed Source/SDK lifecycle quote fields without new authority.
//!
//! ```text
//! {sdk,source:{retained,transient,scratch},guard_window}
//! ```

use super::*;
use serde::{Serialize, Serializer, ser::SerializeStruct};

struct History<'a>(&'a PacketCompleteInitialLifecycleQuote);

impl PacketCompleteInitialLifecycleQuote {
    /// Borrows the complete defining owner as historical DATA without a live grant.
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn borrowed_settled17_history_data(
        &self,
    ) -> impl Serialize + '_ {
        History(self)
    }

    /// Counts the concrete borrowed, scalar, result and alias-counter views.
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn settled17_history_counter_scratch_data()
    -> usize {
        size_of::<History<'static>>()
            + size_of::<[&usize; 4]>()
            + PacketNativeHostInitialLifecycleStorageData::settled17_history_counter_scratch_data()
    }
}

impl Serialize for History<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let PacketCompleteInitialLifecycleQuote {
            sdk,
            source,
            guard_window,
        } = self.0;
        let OriginalInitialSourceStorage {
            retained,
            transient,
            scratch,
        } = source;
        let mut state =
            serializer.serialize_struct("HistoricalSourceInitialLifecycleQuote17", 3)?;
        state.serialize_field("sdk", &sdk.borrowed_settled17_history_data())?;
        state.serialize_field("source", &(retained, transient, scratch))?;
        state.serialize_field("guard_window", guard_window)?;
        state.end()
    }
}
