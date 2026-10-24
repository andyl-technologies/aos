//! Borrows every Source-owned SDK marker flag, original quote and launch edge.
//!
//! ```text
//! {origin_edge,origin:null|{role,inline_bytes},complete,initial_lifecycle_issued,
//!  initial_lifecycle_quote,initial_lifecycle_completed,launch}
//! ```

use super::*;

use crate::node_contract::restored_owner_history::{
    OriginalRestoredOwnerCapacityAliases as Aliases,
    finalizers17::{add_demands, weak_demand, weak_edge},
};
use serde::{Serialize, Serializer, ser::SerializeStruct};
use std::cell::RefCell;

struct History<'a> {
    original: &'a OriginalHostStartupMarker,
    aliases: &'a RefCell<Aliases>,
}

impl OriginalHostStartupMarker {
    /// Borrows the complete defining owner as historical DATA without a live grant.
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn borrowed_settled17_history_data<
        'a,
    >(
        &'a self,
        aliases: &'a RefCell<Aliases>,
    ) -> impl Serialize + 'a {
        History {
            original: self,
            aliases,
        }
    }

    /// Counts actual capacity rows and shared alias occurrences before allocation.
    ///
    /// # Errors
    /// Refuses a foreign/busy original or checked traversal and population overflow.
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn settled17_history_metadata_demand_data(
        &self,
    ) -> Result<(usize, usize), RuntimeError> {
        add_demands(&[
            weak_demand(&self.origin),
            self.launch
                .as_ref()
                .map(|launch| launch.settled17_history_metadata_demand_data())
                .transpose()?
                .unwrap_or((0, 0)),
        ])
    }

    /// Counts the concrete borrowed, scalar, result and alias-counter views.
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn settled17_history_counter_scratch_data()
    -> usize {
        size_of::<[(usize, usize); 2]>() + size_of::<History<'static>>()
            + size_of::<Option<History<'static>>>()
            + size_of::<&Option<History<'static>>>() + size_of::<Rc<OriginalHostSdkOrigin>>()
            + size_of::<Option<Rc<OriginalHostSdkOrigin>>>()
            + size_of::<Option<(&'static str, usize)>>()
            + size_of::<[&bool; 3]>()
            + PacketCompleteInitialLifecycleQuote::settled17_history_counter_scratch_data()
            + crate::node_adapters::cnp::semantic::process::OriginalHostLaunchIdentity::settled17_history_counter_scratch_data()
            + crate::node_contract::restored_owner_history::finalizers17::counter_scratch_data()
    }
}

impl Serialize for History<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::Error;
        let OriginalHostStartupMarker {
            origin,
            complete,
            initial_lifecycle_issued,
            initial_lifecycle_quote,
            initial_lifecycle_completed,
            launch,
        } = self.original;
        let edge = weak_edge(origin, self.aliases).map_err(S::Error::custom)?;
        let upgraded = origin.upgrade();
        let body = upgraded
            .as_ref()
            .map(|origin| {
                origin.ensure_current()?;
                Ok::<_, RuntimeError>((
                    "original-source-process-thread",
                    size_of::<OriginalHostSdkOrigin>(),
                ))
            })
            .transpose()
            .map_err(S::Error::custom)?;
        let quote = initial_lifecycle_quote
            .as_ref()
            .map(|quote| quote.borrowed_settled17_history_data());
        let launch = launch
            .as_ref()
            .map(|launch| launch.borrowed_settled17_history_data(self.aliases))
            .transpose()
            .map_err(S::Error::custom)?;
        let mut state = serializer.serialize_struct("HistoricalHostStartupMarker17", 7)?;
        state.serialize_field("origin_edge", &edge)?;
        state.serialize_field("origin", &body)?;
        state.serialize_field("complete", complete)?;
        state.serialize_field("initial_lifecycle_issued", initial_lifecycle_issued)?;
        state.serialize_field("initial_lifecycle_quote", &quote)?;
        state.serialize_field("initial_lifecycle_completed", initial_lifecycle_completed)?;
        state.serialize_field("launch", &launch)?;
        let result = state.end()?;
        if let Some(origin) = upgraded.as_ref() {
            origin.ensure_current().map_err(S::Error::custom)?;
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marker_history_preserves_each_once_flag_and_expired_origin_without_reissue() {
        // No SDK, Source or initial-lifecycle member is constructed by this test.
        let origin = Rc::new(OriginalHostSdkOrigin::new());
        let mut marker = OriginalHostStartupMarker {
            origin: Rc::downgrade(&origin),
            complete: false,
            initial_lifecycle_issued: false,
            initial_lifecycle_quote: None,
            initial_lifecycle_completed: false,
            launch: None,
        };
        let mut slot = None;
        Aliases::reserve_into(1, &mut slot).unwrap();
        let aliases = RefCell::new(slot.unwrap());
        let initial =
            serde_json::to_value(marker.borrowed_settled17_history_data(&aliases)).unwrap();
        assert_eq!(initial["complete"], false);
        assert_eq!(initial["initial_lifecycle_issued"], false);
        assert_eq!(initial["initial_lifecycle_completed"], false);
        assert_eq!(initial["initial_lifecycle_quote"], serde_json::Value::Null);
        assert_eq!(initial["launch"], serde_json::Value::Null);
        assert_eq!(initial["origin_edge"]["length"], 1);
        assert_eq!(Rc::strong_count(&origin), 1);

        marker.complete = true;
        marker.initial_lifecycle_issued = true;
        let issued =
            serde_json::to_value(marker.borrowed_settled17_history_data(&aliases)).unwrap();
        assert_eq!(issued["complete"], true);
        assert_eq!(issued["initial_lifecycle_issued"], true);
        assert_eq!(issued["initial_lifecycle_completed"], false);
        marker.initial_lifecycle_completed = true;
        drop(origin);
        let expired =
            serde_json::to_value(marker.borrowed_settled17_history_data(&aliases)).unwrap();
        assert_eq!(expired["origin"], serde_json::Value::Null);
        assert_eq!(expired["origin_edge"]["length"], 0);
        assert_eq!(
            expired["origin_edge"]["shared_group"],
            initial["origin_edge"]["shared_group"]
        );
        assert_eq!(expired["initial_lifecycle_issued"], true);
        assert_eq!(expired["initial_lifecycle_completed"], true);
        assert_eq!(
            marker.settled17_history_metadata_demand_data().unwrap(),
            (1, 1)
        );
    }
}
