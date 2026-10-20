//! Borrows the consumed suffix startup member and both original wire-once flags.
//!
//! ```text
//! {origin_role,source,plan,reservation,construction,wire_attempted,wire_completed}
//! Startup17 additionally carries `settled` with its actual fixed quote,
//! construction and separate attempted/completed flags. Startup16 keeps its
//! original seven-field representation.
//! ```

use super::*;

use crate::node_contract::restored_owner_history::{
    OriginalRestoredOwnerCapacityAliases as Aliases,
    finalizers17::{add_demands, shared_edge, weak_demand, weak_edge},
};
use serde::{Serialize, Serializer, ser::SerializeStruct};
use std::cell::RefCell;

struct History<'a> {
    original: &'a OriginalRestoredSuffixStartupMember,
    source: &'a PacketCompleteSemanticSource,
    aliases: &'a RefCell<Aliases>,
}

impl OriginalRestoredSuffixStartupMember {
    fn history17_origin(&self, source: &PacketCompleteSemanticSource) -> Result<(), RuntimeError> {
        if self.process != std::process::id() {
            return Err(RuntimeError::ForeignAuthority);
        }
        if self.thread != std::thread::current().id() {
            return Err(RuntimeError::ThreadAffinity);
        }
        if !std::ptr::eq(self.source.as_ptr(), source) {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }

    /// Borrows the complete defining owner as historical DATA without a live grant.
    ///
    /// # Errors
    /// Refuses a foreign original process/thread or Source association.
    pub(crate) fn borrowed_settled17_history_data<'a>(
        &'a self,
        source: &'a PacketCompleteSemanticSource,
        aliases: &'a RefCell<Aliases>,
    ) -> Result<impl Serialize + 'a, RuntimeError> {
        self.history17_origin(source)?;
        Ok(History {
            original: self,
            source,
            aliases,
        })
    }

    /// Counts actual capacity rows and shared alias occurrences before allocation.
    ///
    /// # Errors
    /// Refuses a foreign/busy original or checked traversal and population overflow.
    pub(crate) fn settled17_history_metadata_demand_data(
        &self,
        source: &PacketCompleteSemanticSource,
    ) -> Result<(usize, usize), RuntimeError> {
        self.history17_origin(source)?;
        add_demands(&[weak_demand(&self.source), weak_demand(&self.plan.0)])
    }

    /// Counts the concrete borrowed, scalar, result and alias-counter views.
    pub(crate) fn settled17_history_counter_scratch_data() -> usize {
        size_of::<[(usize, usize); 2]>()
            + size_of::<History<'static>>()
            + size_of::<Option<History<'static>>>()
            + size_of::<Option<Result<History<'static>, RuntimeError>>>()
            + size_of::<Result<Option<History<'static>>, RuntimeError>>()
            + size_of::<Result<History<'static>, RuntimeError>>()
            + size_of::<(bool, bool)>() * 2
            + PacketNativeRestoredSuffixStartupStorageData::settled17_history_counter_scratch_data()
            + PacketNativeSuffixConstructionStorageData::settled17_history_counter_scratch_data()
            + super::settled::OriginalRestoredSettledStartupMember::history17_counter_scratch_data()
            + crate::node_contract::restored_owner_history::finalizers17::counter_scratch_data()
    }
}

impl Serialize for History<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::Error;
        let owner = self.original;
        owner
            .history17_origin(self.source)
            .map_err(S::Error::custom)?;
        let OriginalRestoredSuffixStartupMember {
            process: _,
            thread: _,
            source,
            plan,
            rows,
            wire_attempted,
            wire_completed,
            settled,
        } = owner;
        let OriginalRestoredSuffixStartupRows {
            reservation,
            construction,
        } = rows;
        let observed = (wire_attempted.get(), wire_completed.get());
        let fields = if settled.is_some() { 8 } else { 7 };
        let mut state = serializer.serialize_struct("HistoricalSuffixStartupMember17", fields)?;
        state.serialize_field("origin_role", "original-source-process-thread")?;
        state.serialize_field(
            "source",
            &weak_edge(source, self.aliases).map_err(S::Error::custom)?,
        )?;
        state.serialize_field(
            "plan",
            &weak_edge(&plan.0, self.aliases).map_err(S::Error::custom)?,
        )?;
        state.serialize_field(
            "reservation",
            &reservation.borrowed_settled17_history_data(),
        )?;
        state.serialize_field(
            "construction",
            &construction.borrowed_settled17_history_data(),
        )?;
        state.serialize_field("wire_attempted", &observed.0)?;
        state.serialize_field("wire_completed", &observed.1)?;
        if let Some(settled) = settled {
            state.serialize_field("settled", &settled.borrowed_history17_data())?;
        }
        let result = state.end()?;
        owner
            .history17_origin(self.source)
            .map_err(S::Error::custom)?;
        if observed != (wire_attempted.get(), wire_completed.get()) {
            return Err(S::Error::custom(RuntimeError::ForeignAuthority));
        }
        Ok(result)
    }
}
