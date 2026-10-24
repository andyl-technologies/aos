//! Borrows all sealed initial-lifecycle quote axes as historical DATA.
//!
//! ```text
//! {retained,transient,scratch,journal_growth,source_assigned_admit}
//! ```

use super::*;
use serde::{Serialize, Serializer, ser::SerializeStruct};

struct History<'a>(&'a PacketNativeHostInitialLifecycleStorageData);

impl PacketNativeHostInitialLifecycleStorageData {
    /// Borrows every sealed quote field without constructing lifecycle authority.
    pub fn borrowed_settled17_history_data(&self) -> impl Serialize + '_ {
        History(self)
    }

    /// Counts the concrete borrowed quote and serializer field views.
    pub fn settled17_history_counter_scratch_data() -> usize {
        size_of::<History<'static>>() + size_of::<[&usize; 5]>()
    }
}

impl Serialize for History<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let PacketNativeHostInitialLifecycleStorageData {
            retained,
            transient,
            scratch,
            journal_growth,
            source_assigned_admit,
        } = self.0;
        let mut state = serializer.serialize_struct("HistoricalInitialLifecycleQuote17", 5)?;
        state.serialize_field("retained", retained)?;
        state.serialize_field("transient", transient)?;
        state.serialize_field("scratch", scratch)?;
        state.serialize_field("journal_growth", journal_growth)?;
        state.serialize_field("source_assigned_admit", source_assigned_admit)?;
        state.end()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sealed_quote_history_keeps_independent_journal_and_source_axes() {
        let quote = PacketNativeHostInitialLifecycleStorageData {
            retained: 13,
            transient: 17,
            scratch: 19,
            journal_growth: 23,
            source_assigned_admit: 29,
        };
        let body = serde_json::to_value(quote.borrowed_settled17_history_data()).unwrap();

        assert_eq!(
            body,
            serde_json::json!({"retained":13,"transient":17,"scratch":19,
            "journal_growth":23,"source_assigned_admit":29})
        );
        assert_eq!(quote.journal_growth_data(), 23);
        assert_eq!(quote.source_assigned_admit_requested_bytes_data(), 29);
        assert_eq!(quote.requested_peak_data().unwrap(), 49);
    }
}
