//! Borrows the original shared host barrier and its once-only phase as DATA.
//!
//! ```text
//! barrier = {origin_role,plan,sources:[weak;3],completed,active,aborted}
//! link = {index,barrier_edge,barrier:null|barrier}
//! ```

use super::*;

use crate::node_contract::restored_owner_history::{
    OriginalRestoredOwnerCapacityAliases as Aliases,
    finalizers17::{add_demands, shared_edge, weak_demand, weak_edge},
};
use serde::{Serialize, Serializer, ser::SerializeStruct};
use std::cell::RefCell;

struct Barrier<'a> {
    original: &'a OriginalHostFinalizationBarrier,
    source: &'a PacketCompleteSemanticSource,
    index: usize,
    aliases: &'a RefCell<Aliases>,
}
struct Source<'a> {
    original: &'a OriginalHostFinalizationSource,
    source: &'a PacketCompleteSemanticSource,
    aliases: &'a RefCell<Aliases>,
}

impl OriginalHostFinalizationBarrier {
    fn history17_origin(
        &self,
        index: usize,
        source: &PacketCompleteSemanticSource,
    ) -> Result<(), RuntimeError> {
        self.origin.authenticate()?;
        if self
            .sources
            .get(index)
            .is_none_or(|owner| !std::ptr::eq(owner.as_ptr(), source))
        {
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
        index: usize,
        aliases: &'a RefCell<Aliases>,
    ) -> Result<impl Serialize + 'a, RuntimeError> {
        self.history17_origin(index, source)?;
        Ok(Barrier {
            original: self,
            source,
            index,
            aliases,
        })
    }

    /// Counts actual capacity rows and shared alias occurrences before allocation.
    ///
    /// # Errors
    /// Refuses a foreign/busy original or checked traversal and population overflow.
    pub(crate) fn settled17_history_metadata_demand_data(
        &self,
    ) -> Result<(usize, usize), RuntimeError> {
        self.origin.authenticate()?;
        add_demands(&[
            weak_demand(&self.plan.0),
            weak_demand(&self.sources[0]),
            weak_demand(&self.sources[1]),
            weak_demand(&self.sources[2]),
        ])
    }

    /// Counts the concrete borrowed, scalar, result and alias-counter views.
    pub(crate) fn settled17_history_counter_scratch_data() -> usize {
        size_of::<[(usize, usize); 4]>()
            + size_of::<Barrier<'static>>()
            + size_of::<Option<Source<'static>>>()
            + size_of::<&Option<Source<'static>>>()
            + size_of::<Option<Result<Barrier<'static>, RuntimeError>>>()
            + size_of::<Result<Option<Barrier<'static>>, RuntimeError>>()
            + size_of::<Source<'static>>()
            + size_of::<[(usize, usize); 2]>()
            + size_of::<
                [Result<
                    crate::node_contract::restored_owner_history::OriginalRestoredOwnerCapacityRow,
                    RuntimeError,
                >; 3],
            >()
            + size_of::<Rc<Self>>()
            + size_of::<Option<Rc<Self>>>()
            + size_of::<Result<Barrier<'static>, RuntimeError>>()
            + size_of::<(u8, Option<usize>, bool)>() * 2
            + size_of::<
                [crate::node_contract::restored_owner_history::OriginalRestoredOwnerCapacityRow; 3],
            >()
            + crate::node_contract::restored_owner_history::finalizers17::counter_scratch_data()
    }
}

impl OriginalHostFinalizationSource {
    /// Borrows the complete defining owner as historical DATA without a live grant.
    pub(crate) fn borrowed_settled17_history_data<'a>(
        &'a self,
        source: &'a PacketCompleteSemanticSource,
        aliases: &'a RefCell<Aliases>,
    ) -> impl Serialize + 'a {
        Source {
            original: self,
            source,
            aliases,
        }
    }

    /// Counts actual capacity rows and shared alias occurrences before allocation.
    ///
    /// # Errors
    /// Refuses a foreign/busy original or checked traversal and population overflow.
    pub(crate) fn settled17_history_metadata_demand_data(
        &self,
    ) -> Result<(usize, usize), RuntimeError> {
        let owner = self.barrier.upgrade();
        add_demands(&[
            weak_demand(&self.barrier),
            owner
                .as_ref()
                .map(|barrier| barrier.settled17_history_metadata_demand_data())
                .transpose()?
                .unwrap_or((0, 0)),
        ])
    }

    /// Counts the same retained shared allocation without deduplication credit.
    pub(crate) fn settled17_history_retained_heap_data(&self) -> usize {
        if self.barrier.ptr_eq(&Weak::new()) {
            0
        } else {
            OriginalHostFinalizationBarrier::allocation_requested_bytes()
        }
    }
}

impl Serialize for Barrier<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::Error;
        let owner = self.original;
        owner
            .history17_origin(self.index, self.source)
            .map_err(S::Error::custom)?;
        let OriginalHostFinalizationBarrier {
            origin: _,
            plan,
            sources,
            phase,
        } = owner;
        let HostPhase {
            completed,
            active,
            aborted,
        } = phase;
        let observed = (completed.get(), active.get(), aborted.get());
        let mut state = serializer.serialize_struct("HistoricalHostFinalizationBarrier17", 6)?;
        state.serialize_field("origin_role", "original-source-process-thread")?;
        state.serialize_field(
            "plan",
            &weak_edge(&plan.0, self.aliases).map_err(S::Error::custom)?,
        )?;
        let edges = [
            weak_edge(&sources[0], self.aliases),
            weak_edge(&sources[1], self.aliases),
            weak_edge(&sources[2], self.aliases),
        ];
        let [first, second, third] = edges;
        let edges = [
            first.map_err(S::Error::custom)?,
            second.map_err(S::Error::custom)?,
            third.map_err(S::Error::custom)?,
        ];
        state.serialize_field("sources", &edges)?;
        state.serialize_field("completed", &observed.0)?;
        state.serialize_field("active", &observed.1)?;
        state.serialize_field("aborted", &observed.2)?;
        let result = state.end()?;
        owner
            .history17_origin(self.index, self.source)
            .map_err(S::Error::custom)?;
        if observed != (completed.get(), active.get(), aborted.get()) {
            return Err(S::Error::custom(RuntimeError::ForeignAuthority));
        }
        Ok(result)
    }
}

impl Serialize for Source<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::Error;
        let OriginalHostFinalizationSource { barrier, index } = self.original;
        // Observe the weak edge before the temporary read upgrade changes its
        // strong count. This loan cannot escape the historical serializer.
        let edge = weak_edge(barrier, self.aliases).map_err(S::Error::custom)?;
        let upgraded = barrier.upgrade();
        let body = upgraded
            .as_ref()
            .map(|owner| owner.borrowed_settled17_history_data(self.source, *index, self.aliases))
            .transpose()
            .map_err(S::Error::custom)?;
        let mut state = serializer.serialize_struct("HistoricalHostFinalizationSource17", 3)?;
        state.serialize_field("index", index)?;
        state.serialize_field("barrier_edge", &edge)?;
        state.serialize_field("barrier", &body)?;
        state.end()
    }
}
