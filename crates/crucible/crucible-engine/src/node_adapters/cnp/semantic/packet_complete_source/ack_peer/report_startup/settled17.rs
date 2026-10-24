//! Borrows the complete original finalizer, its member and every retained partial.
//!
//! ```text
//! {member,replacement,replacement_capacities,body,body_capacities,
//!  additions,additions_capacities,complete}
//! ```

use super::*;

use crate::node_contract::{
    RuntimeError,
    restored_owner_history::{
        OriginalRestoredOwnerCapacityAliases as Aliases,
        OriginalRestoredOwnerCapacityRows as Capacities, finalizers17::add_demands,
    },
};
use crucible_node_transport::protocol_snapshot::compact_bytes::BorrowedCompactBytes;
use serde::{Serialize, Serializer, ser::SerializeStruct};
use std::{cell::RefCell, mem::size_of};

struct History<'a> {
    original: &'a OriginalReportStartupFinalization,
    source: &'a PacketCompleteSemanticSource,
    aliases: &'a RefCell<Aliases>,
}

impl OriginalReportStartupFinalization {
    /// Borrows the complete defining owner as historical DATA without a live grant.
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn borrowed_settled17_history_data<
        'a,
    >(
        &'a self,
        source: &'a PacketCompleteSemanticSource,
        aliases: &'a RefCell<Aliases>,
    ) -> impl Serialize + 'a {
        History {
            original: self,
            source,
            aliases,
        }
    }

    /// Counts actual capacity rows and shared alias occurrences before allocation.
    ///
    /// # Errors
    /// Refuses a foreign/busy original or checked traversal and population overflow.
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn settled17_history_metadata_demand_data(
        &self,
        source: &PacketCompleteSemanticSource,
    ) -> Result<(usize, usize), RuntimeError> {
        add_demands(&[
            self.member.settled17_history_metadata_demand_data(source)?,
            Capacities(&self.replacement).metadata_demand_data()?,
            Capacities(&self.body).metadata_demand_data()?,
            Capacities(&self.additions).metadata_demand_data()?,
        ])
    }

    /// Counts the concrete borrowed, scalar, result and alias-counter views.
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn settled17_history_counter_scratch_data()
    -> usize {
        size_of::<[(usize, usize); 4]>() + size_of::<History<'static>>()
            + size_of::<Option<History<'static>>>()
            + size_of::<&Option<History<'static>>>() + size_of::<&Vec<u8>>()
            + size_of::<&Option<serde_json::Value>>() * 2 + size_of::<&bool>()
            + size_of::<BorrowedCompactBytes<'static>>()
            + BorrowedCompactBytes::requested_serialization_scratch_bytes()
            + crate::node_admission::OriginalReportStartupMember::settled17_history_counter_scratch_data()
            + crate::node_contract::restored_owner_history::finalizers17::counter_scratch_data()
    }
}

impl Serialize for History<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::Error;
        let OriginalReportStartupFinalization {
            member,
            replacement,
            body,
            additions,
            complete,
        } = self.original;
        let member = member
            .borrowed_settled17_history_data(self.source, self.aliases)
            .map_err(S::Error::custom)?;
        let mut state =
            serializer.serialize_struct("HistoricalOriginalReportStartupFinalization17", 8)?;
        state.serialize_field("member", &member)?;
        state.serialize_field("replacement", &BorrowedCompactBytes::new(replacement))?;
        state.serialize_field(
            "replacement_capacities",
            &Capacities(replacement).with_aliases(self.aliases),
        )?;
        state.serialize_field("body", body)?;
        state.serialize_field(
            "body_capacities",
            &Capacities(body).with_aliases(self.aliases),
        )?;
        state.serialize_field("additions", additions)?;
        state.serialize_field(
            "additions_capacities",
            &Capacities(additions).with_aliases(self.aliases),
        )?;
        state.serialize_field("complete", complete)?;
        state.end()
    }
}
