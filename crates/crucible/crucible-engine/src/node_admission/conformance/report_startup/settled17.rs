//! Borrows the actual report member's weak associations and complete fixed rows.
//!
//! ```text
//! {origin_role,plan,source,rows:{original_observe12,fresh_completed_admit13},finalization_bytes}
//! ```

use super::*;
use crate::node_contract::RuntimeError;

use crate::node_contract::restored_owner_history::{
    OriginalRestoredOwnerCapacityAliases as Aliases,
    finalizers17::{add_demands, shared_edge, weak_demand, weak_edge},
};
use serde::{Serialize, Serializer, ser::SerializeStruct};
use std::cell::RefCell;

struct Rows<'a>(&'a StartupRows);
struct Member<'a> {
    member: &'a OriginalReportStartupMember,
    source: &'a PacketCompleteSemanticSource,
    aliases: &'a RefCell<Aliases>,
}

impl StartupRows {
    /// Borrows the complete defining owner as historical DATA without a live grant.
    pub(crate) fn borrowed_settled17_history_data(&self) -> impl Serialize + '_ {
        Rows(self)
    }
}

impl Serialize for Rows<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let StartupRows {
            original_observe12,
            fresh_completed_admit13,
        } = self.0;
        let mut state = serializer.serialize_struct("HistoricalReportStartupRows17", 2)?;
        state.serialize_field("original_observe12", original_observe12)?;
        state.serialize_field("fresh_completed_admit13", fresh_completed_admit13)?;
        state.end()
    }
}

impl OriginalReportStartupMember {
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
        Ok(Member {
            member: self,
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
        add_demands(&[weak_demand(&self.plan.0), weak_demand(&self.source)])
    }

    /// Counts the concrete borrowed, scalar, result and alias-counter views.
    pub(crate) fn settled17_history_counter_scratch_data() -> usize {
        size_of::<Member<'static>>()
            + size_of::<Rows<'static>>()
            + size_of::<Result<Member<'static>, RuntimeError>>()
            + size_of::<[&usize; 1]>()
            + size_of::<[&'static str; 1]>()
            + crate::node_contract::restored_owner_history::finalizers17::counter_scratch_data()
            + size_of::<[(usize, usize); 2]>()
    }
}

impl Serialize for Member<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::Error;
        let owner = self.member;
        owner
            .history17_origin(self.source)
            .map_err(S::Error::custom)?;
        let OriginalReportStartupMember {
            plan,
            source,
            process: _,
            thread: _,
            rows,
            finalization_bytes,
        } = owner;
        let mut state = serializer.serialize_struct("HistoricalReportStartupMember17", 5)?;
        state.serialize_field("origin_role", "original-source-process-thread")?;
        state.serialize_field(
            "plan",
            &weak_edge(&plan.0, self.aliases).map_err(S::Error::custom)?,
        )?;
        state.serialize_field(
            "source",
            &weak_edge(source, self.aliases).map_err(S::Error::custom)?,
        )?;
        state.serialize_field("rows", &rows.borrowed_settled17_history_data())?;
        state.serialize_field("finalization_bytes", finalization_bytes)?;
        let result = state.end()?;
        owner
            .history17_origin(self.source)
            .map_err(S::Error::custom)?;
        Ok(result)
    }
}
