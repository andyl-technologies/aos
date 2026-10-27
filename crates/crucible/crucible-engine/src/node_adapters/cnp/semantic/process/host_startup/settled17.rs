//! Borrows the retained launch identity and actual weak read-owner state as DATA.
//!
//! ```text
//! {origin_role,owner_edge,owner:null|{identity,current,busy}}
//! ```

use super::*;

use crate::node_contract::restored_owner_history::{
    OriginalRestoredOwnerCapacityAliases as Aliases,
    finalizers17::{add_demands, weak_demand, weak_edge},
};
use serde::{Serialize, Serializer, ser::SerializeStruct};
use std::cell::RefCell;

struct History<'a> {
    original: &'a OriginalHostLaunchIdentity,
    aliases: &'a RefCell<Aliases>,
}

impl OriginalHostLaunchIdentity {
    fn history17_origin(&self) -> Result<(), RuntimeError> {
        if self.creator != std::process::id() {
            return Err(RuntimeError::ForeignAuthority);
        }
        if self.thread != std::thread::current().id() {
            return Err(RuntimeError::ThreadAffinity);
        }
        Ok(())
    }

    /// Borrows the complete defining owner as historical DATA without a live grant.
    ///
    /// # Errors
    /// Refuses a foreign original process/thread or Source association.
    pub(in crate::node_adapters::cnp::semantic) fn borrowed_settled17_history_data<'a>(
        &'a self,
        aliases: &'a RefCell<Aliases>,
    ) -> Result<impl Serialize + 'a, RuntimeError> {
        self.history17_origin()?;
        Ok(History {
            original: self,
            aliases,
        })
    }

    /// Counts actual capacity rows and shared alias occurrences before allocation.
    ///
    /// # Errors
    /// Refuses a foreign/busy original or checked traversal and population overflow.
    pub(in crate::node_adapters::cnp::semantic) fn settled17_history_metadata_demand_data(
        &self,
    ) -> Result<(usize, usize), RuntimeError> {
        self.history17_origin()?;
        Ok(weak_demand(&self.owner))
    }

    /// Counts the concrete borrowed, scalar, result and alias-counter views.
    pub(in crate::node_adapters::cnp::semantic) fn settled17_history_counter_scratch_data() -> usize
    {
        std::mem::size_of::<History<'static>>()
            + std::mem::size_of::<Option<History<'static>>>()
            + std::mem::size_of::<Option<Result<History<'static>, RuntimeError>>>()
            + std::mem::size_of::<Result<Option<History<'static>>, RuntimeError>>()
            + std::mem::size_of::<Result<History<'static>, RuntimeError>>()
            + std::mem::size_of::<Rc<current::ReadOwner>>()
            + std::mem::size_of::<Option<Rc<current::ReadOwner>>>()
            + current::ReadOwner::settled17_history_counter_scratch_data()
            + crate::node_contract::restored_owner_history::finalizers17::counter_scratch_data()
    }
}

impl Serialize for History<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::Error;
        let owner = self.original;
        owner.history17_origin().map_err(S::Error::custom)?;
        let OriginalHostLaunchIdentity {
            owner: weak,
            creator: _,
            thread: _,
        } = owner;
        let edge = weak_edge(weak, self.aliases).map_err(S::Error::custom)?;
        let upgraded = weak.upgrade();
        let body = upgraded
            .as_ref()
            .map(|read| read.borrowed_settled17_history_data());
        let mut state = serializer.serialize_struct("HistoricalHostLaunchIdentity17", 3)?;
        state.serialize_field("origin_role", "original-source-process-thread")?;
        state.serialize_field("owner_edge", &edge)?;
        state.serialize_field("owner", &body)?;
        let result = state.end()?;
        owner.history17_origin().map_err(S::Error::custom)?;
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn launch_history_keeps_same_alias_revocation_and_expired_weak_state() {
        // These private DATA owners do not create a launch guard, Child or grant.
        let read = Rc::new(current::ReadOwner::new(crucible_node_format::U64::new(17)));
        let identity = OriginalHostLaunchIdentity {
            owner: Rc::downgrade(&read),
            creator: std::process::id(),
            thread: std::thread::current().id(),
        };
        let mut slot = None;
        Aliases::reserve_into(1, &mut slot).unwrap();
        let aliases = RefCell::new(slot.unwrap());
        let shared =
            serde_json::to_value(aliases.borrow_mut().shared_owner_data(&read).unwrap()).unwrap();
        let before =
            serde_json::to_value(identity.borrowed_settled17_history_data(&aliases).unwrap())
                .unwrap();

        assert_eq!(before["owner_edge"]["shared_group"], shared["shared_group"]);
        assert_eq!(before["owner_edge"]["length"], 1);
        assert_eq!(
            before["owner"]["identity"],
            serde_json::to_value(crucible_node_format::U64::new(17)).unwrap()
        );
        assert_eq!(before["owner"]["current"], true);
        assert_eq!(before["owner"]["busy"], false);
        assert_eq!(Rc::strong_count(&read), 1);

        read.revoke();
        let revoked =
            serde_json::to_value(identity.borrowed_settled17_history_data(&aliases).unwrap())
                .unwrap();
        assert_eq!(revoked["owner"]["current"], false);
        assert_eq!(
            identity.settled17_history_metadata_demand_data().unwrap(),
            (1, 1)
        );
        drop(read);
        let expired =
            serde_json::to_value(identity.borrowed_settled17_history_data(&aliases).unwrap())
                .unwrap();
        assert_eq!(expired["owner"], serde_json::Value::Null);
        assert_eq!(expired["owner_edge"]["length"], 0);
        assert_eq!(
            expired["owner_edge"]["shared_group"],
            before["owner_edge"]["shared_group"]
        );
        assert_eq!(
            identity.settled17_history_metadata_demand_data().unwrap(),
            (1, 1)
        );
    }
}
