//! Borrows the actual launch read-owner identity and current/busy phase as DATA.
//!
//! ```text
//! {identity,current,busy}
//! ```

use super::*;
use serde::{Serialize, Serializer, ser::SerializeStruct};

struct History<'a>(&'a ReadOwner);

impl ReadOwner {
    /// Borrows the complete defining owner as historical DATA without a live grant.
    pub(in crate::node_adapters::cnp::semantic) fn borrowed_settled17_history_data(
        &self,
    ) -> impl Serialize + '_ {
        History(self)
    }

    /// Counts the concrete borrowed, scalar, result and alias-counter views.
    pub(in crate::node_adapters::cnp::semantic) fn settled17_history_counter_scratch_data() -> usize
    {
        std::mem::size_of::<History<'static>>()
            + std::mem::size_of::<(bool, bool)>() * 2
            + std::mem::size_of::<&U64>()
    }
}

impl Serialize for History<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::Error;
        let ReadOwner {
            identity,
            current,
            busy,
        } = self.0;
        let observed = (current.get(), busy.get());
        let mut state = serializer.serialize_struct("HistoricalLaunchReadOwner17", 3)?;
        state.serialize_field("identity", identity)?;
        state.serialize_field("current", &observed.0)?;
        state.serialize_field("busy", &observed.1)?;
        let result = state.end()?;
        if observed != (current.get(), busy.get()) {
            return Err(S::Error::custom(
                crate::node_contract::RuntimeError::ForeignAuthority,
            ));
        }
        Ok(result)
    }
}
