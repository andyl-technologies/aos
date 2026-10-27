//! Records local shared edges without publishing or dereferencing pointers.
//!
//! A serializer pass retains the borrowed original owners while this finite
//! lookup compares their backing addresses. Only first-group ordinals cross
//! the historical format; no label reconstructs a live authority allocation.

use super::*;

/// Owns a separately precharged temporary shared-edge lookup for one cut.
pub(crate) struct OriginalRestoredOwnerCapacityAliases {
    identities: Vec<*const ()>,
    maximum: usize,
    comparisons: usize,
    attempted: bool,
    ready: bool,
}

impl OriginalRestoredOwnerCapacityAliases {
    /// Quotes only the lookup backing; its inline root is a separate term.
    ///
    /// # Errors
    /// Refuses zero, excessive population or checked backing overflow.
    pub(crate) fn requested_bytes(maximum: usize) -> Result<usize, RuntimeError> {
        if maximum == 0 || maximum > MAXIMUM_ROWS {
            return Err(RuntimeError::ResourceLimit);
        }
        maximum
            .checked_mul(size_of::<*const ()>())
            .ok_or(RuntimeError::ResourceLimit)
    }

    /// Creates an unallocated DATA lookup for retention before reservation.
    ///
    /// # Errors
    /// Refuses an invalid or overflowing prospective population.
    pub(crate) fn unallocated(maximum: usize) -> Result<Self, RuntimeError> {
        Self::requested_bytes(maximum)?;
        Ok(Self {
            identities: Vec::new(),
            maximum,
            comparisons: 0,
            attempted: false,
            ready: false,
        })
    }

    /// Reserves this same retained lookup once, preserving every partial on error.
    ///
    /// # Errors
    /// Refuses another attempt, allocation failure or a capacity beyond the quote.
    pub(crate) fn reserve(&mut self) -> Result<(), RuntimeError> {
        let requested = Self::requested_bytes(self.maximum)?;
        if self.attempted || !self.identities.is_empty() || self.identities.capacity() != 0 {
            return Err(RuntimeError::OutstandingObligations);
        }
        self.attempted = true;
        self.identities
            .try_reserve_exact(self.maximum)
            .map_err(|_| RuntimeError::ResourceLimit)?;
        if self.allocated_bytes()? > requested {
            return Err(RuntimeError::ResourceLimit);
        }
        self.ready = true;
        Ok(())
    }

    /// Retains the empty owner before the first fallible allocation.
    ///
    /// # Errors
    /// Refuses a populated slot, invalid demand or failed bounded reservation.
    pub(crate) fn reserve_into(
        maximum: usize,
        completed: &mut Option<Self>,
    ) -> Result<(), RuntimeError> {
        if completed.is_some() {
            return Err(RuntimeError::OutstandingObligations);
        }
        *completed = Some(Self::unallocated(maximum)?);
        completed
            .as_mut()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .reserve()
    }

    /// Reports actual lookup capacity, including an interrupted reservation.
    ///
    /// # Errors
    /// Refuses checked backing-size overflow.
    pub(crate) fn allocated_bytes(&self) -> Result<usize, RuntimeError> {
        self.identities
            .capacity()
            .checked_mul(size_of::<*const ()>())
            .ok_or(RuntimeError::ResourceLimit)
    }

    /// Starts a new serialization pass without changing any historical owner.
    ///
    /// The enclosing writer calls this once for the whole history graph, never
    /// between independent owner views whose shared edges must remain linked.
    ///
    /// # Errors
    /// Refuses a lookup whose original reservation did not complete.
    pub(crate) fn begin_pass(&mut self) -> Result<(), RuntimeError> {
        if !self.ready {
            return Err(RuntimeError::ResourceLimit);
        }
        self.identities.clear();
        self.comparisons = 0;
        Ok(())
    }

    /// Records a real retained shared-role edge without exposing its address.
    ///
    /// The defining owner supplies its actual Rc while the entire graph stays
    /// borrowed. The caller serializes a separate definition; this row contains
    /// only layout and a pass-local group, never a source or ticket permission.
    ///
    /// # Errors
    /// Refuses an unreserved, full or traversal-exhausted lookup without growth.
    pub(crate) fn shared_owner_data<T: ?Sized>(
        &mut self,
        owner: &Rc<T>,
    ) -> Result<OriginalRestoredOwnerCapacityRow, RuntimeError> {
        let group = self.group(Rc::as_ptr(owner).cast())?;
        Ok(OriginalRestoredOwnerCapacityRow {
            kind: "shared",
            length: 1,
            capacity: None,
            element_bytes: size_of_val(owner.as_ref()),
            alignment: align_of_val(owner.as_ref()),
            shared_group: Some(group),
            identity: None,
        })
    }

    /// Records an actual shared payload loan without exposing its owner handle.
    ///
    /// The defining caller separately proves that the borrowed payload belongs
    /// to its retained shared owner. This supports an internal Arc<File> loan
    /// without an Arc/FD extractor. Only the same payload address is compared;
    /// no address is encoded or used to access memory. It creates no live role.
    ///
    /// # Errors
    /// Refuses an unreserved, full or traversal-exhausted lookup without growth.
    pub(crate) fn shared_backing_data<T: ?Sized>(
        &mut self,
        backing: &T,
    ) -> Result<OriginalRestoredOwnerCapacityRow, RuntimeError> {
        let group = self.group((backing as *const T).cast())?;
        Ok(OriginalRestoredOwnerCapacityRow {
            kind: "shared",
            length: 1,
            capacity: None,
            element_bytes: size_of_val(backing),
            alignment: align_of_val(backing),
            shared_group: Some(group),
            identity: None,
        })
    }

    /// Records the same actual shared Arc role without reading its payload.
    ///
    /// # Errors
    /// Refuses an unreserved, full or traversal-exhausted lookup without growth.
    pub(crate) fn shared_arc_owner_data<T: ?Sized>(
        &mut self,
        owner: &std::sync::Arc<T>,
    ) -> Result<OriginalRestoredOwnerCapacityRow, RuntimeError> {
        let group = self.group(std::sync::Arc::as_ptr(owner).cast())?;
        Ok(OriginalRestoredOwnerCapacityRow {
            kind: "shared",
            length: 1,
            capacity: None,
            element_bytes: size_of_val(owner.as_ref()),
            alignment: align_of_val(owner.as_ref()),
            shared_group: Some(group),
            identity: None,
        })
    }

    /// Records a real weak edge without upgrading or touching a dead payload.
    ///
    /// `length` is the observed strong-owner count, not an initialized payload
    /// count. The element layout describes T statically; it grants no backing
    /// credit. Empty weak handles have no allocation/group. An expired retained
    /// allocation keeps its same group while its strong count remains zero.
    ///
    /// # Errors
    /// Refuses an unreserved or exhausted lookup for a retained allocation.
    pub(crate) fn weak_owner_data<T>(
        &mut self,
        owner: &std::rc::Weak<T>,
    ) -> Result<OriginalRestoredOwnerCapacityRow, RuntimeError> {
        if !self.ready {
            return Err(RuntimeError::ResourceLimit);
        }
        let group = if owner.ptr_eq(&std::rc::Weak::new()) {
            None
        } else {
            Some(self.group(owner.as_ptr().cast())?)
        };
        Ok(OriginalRestoredOwnerCapacityRow {
            kind: "weak",
            length: owner.strong_count(),
            capacity: None,
            element_bytes: size_of::<T>(),
            alignment: align_of::<T>(),
            shared_group: group,
            identity: None,
        })
    }

    /// Names a retained borrowed identity token without accessing its payload.
    ///
    /// The token comes from its defining original owner. Only equality is used;
    /// no address is serialized and this DATA row grants no access or credit.
    /// A null token has no alias group or initialized payload.
    ///
    /// # Errors
    /// Refuses an unreserved or exhausted pass-local alias bank.
    pub(crate) fn borrowed_identity_data<T>(
        &mut self,
        identity: *const T,
    ) -> Result<OriginalRestoredOwnerCapacityRow, RuntimeError> {
        if !self.ready {
            return Err(RuntimeError::ResourceLimit);
        }
        let group = if identity.is_null() {
            None
        } else {
            Some(self.group(identity.cast())?)
        };
        Ok(OriginalRestoredOwnerCapacityRow {
            kind: "borrowed",
            length: usize::from(!identity.is_null()),
            capacity: None,
            element_bytes: size_of::<T>(),
            alignment: align_of::<T>(),
            shared_group: group,
            identity: None,
        })
    }

    pub(super) fn group(&mut self, identity: *const ()) -> Result<usize, RuntimeError> {
        if !self.ready {
            return Err(RuntimeError::ResourceLimit);
        }
        for (group, actual) in self.identities.iter().enumerate() {
            self.comparisons = self
                .comparisons
                .checked_add(1)
                .ok_or(RuntimeError::ResourceLimit)?;
            if self.comparisons > MAXIMUM_ROWS {
                return Err(RuntimeError::ResourceLimit);
            }
            if *actual == identity {
                return Ok(group);
            }
        }
        if self.identities.len() >= self.maximum
            || self.identities.len() >= self.identities.capacity()
        {
            return Err(RuntimeError::ResourceLimit);
        }
        let group = self.identities.len();
        self.identities.push(identity);
        Ok(group)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::rc::Rc;

    #[test]
    fn actual_shared_edges_keep_groups_and_one_short_never_grows() -> Result<(), RuntimeError> {
        let first = Rc::new(7u8);
        let alias = Rc::clone(&first);
        let independent = Rc::new(7u8);
        let mut slot = None;
        OriginalRestoredOwnerCapacityAliases::reserve_into(1, &mut slot)?;
        let bank = slot.as_mut().ok_or(RuntimeError::OwnerUnavailable)?;
        assert_eq!(bank.group(Rc::as_ptr(&first).cast())?, 0);
        assert_eq!(bank.group(Rc::as_ptr(&alias).cast())?, 0);
        let before = bank.allocated_bytes()?;
        assert_eq!(
            bank.group(Rc::as_ptr(&independent).cast()),
            Err(RuntimeError::ResourceLimit)
        );
        assert_eq!(bank.allocated_bytes()?, before);
        bank.begin_pass()?;
        assert_eq!(bank.group(Rc::as_ptr(&independent).cast())?, 0);
        Ok(())
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "typed shared-role DATA control creates no ticket authority"
)]
mod shared_role_tests {
    use super::*;

    #[test]
    fn typed_shared_role_matches_graph_walk_group_without_publishing_pointer() {
        let owner = Rc::new(String::from("same source DATA"));
        let alias = Rc::clone(&owner);
        let independent = Rc::new(String::from("same source DATA"));
        let mut slot = None;
        OriginalRestoredOwnerCapacityAliases::reserve_into(2, &mut slot).unwrap();
        let aliases = RefCell::new(slot.unwrap());
        let role =
            serde_json::to_value(aliases.borrow_mut().shared_owner_data(&owner).unwrap()).unwrap();
        let actual_walk =
            serde_json::to_value(OriginalRestoredOwnerCapacityRows(&alias).with_aliases(&aliases))
                .unwrap();
        let independent_role = serde_json::to_value(
            aliases
                .borrow_mut()
                .shared_owner_data(&independent)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(role["shared_group"], actual_walk[0]["shared_group"]);
        assert_ne!(role["shared_group"], independent_role["shared_group"]);
        assert_eq!(role["element_bytes"], size_of::<String>());
        assert_eq!(role["alignment"], align_of::<String>());
        assert!(role.get("identity").is_none());
        assert_eq!(aliases.borrow().identities.len(), 2);
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "inert actual shared-kind controls never create authority"
)]
mod shared_kind_tests {
    use super::*;

    #[test]
    fn arc_and_expired_weak_edges_keep_actual_groups_and_empty_weak_has_none() {
        let owner = Rc::new(17u8);
        let weak = Rc::downgrade(&owner);
        let independent_arc = std::sync::Arc::new(17u8);
        let arc_alias = std::sync::Arc::clone(&independent_arc);
        let mut slot = None;
        OriginalRestoredOwnerCapacityAliases::reserve_into(2, &mut slot).unwrap();
        let bank = slot.as_mut().unwrap();
        let first = serde_json::to_value(bank.shared_owner_data(&owner).unwrap()).unwrap();
        let edge = serde_json::to_value(bank.weak_owner_data(&weak).unwrap()).unwrap();
        let arc =
            serde_json::to_value(bank.shared_arc_owner_data(&independent_arc).unwrap()).unwrap();
        let alias = serde_json::to_value(bank.shared_arc_owner_data(&arc_alias).unwrap()).unwrap();
        assert_eq!(first["shared_group"], edge["shared_group"]);
        assert_eq!(arc["shared_group"], alias["shared_group"]);
        assert_ne!(first["shared_group"], arc["shared_group"]);
        assert_eq!(edge["kind"], "weak");
        assert_eq!(edge["length"], 1);
        drop(owner);
        let expired = serde_json::to_value(bank.weak_owner_data(&weak).unwrap()).unwrap();
        assert_eq!(expired["shared_group"], edge["shared_group"]);
        assert_eq!(expired["length"], 0);
        let empty =
            serde_json::to_value(bank.weak_owner_data(&std::rc::Weak::<u8>::new()).unwrap())
                .unwrap();
        assert!(empty["shared_group"].is_null());
        assert_eq!(bank.identities.len(), 2);
        assert!(expired.get("identity").is_none());
        assert!(empty.get("identity").is_none());
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "actual shared payload DATA has no live owner conversion"
)]
mod shared_payload_tests {
    use super::*;

    #[test]
    fn borrowed_payload_and_actual_arc_owner_have_the_same_group_without_extraction() {
        let owner = std::sync::Arc::new(String::from("retained payload"));
        let mut slot = None;
        OriginalRestoredOwnerCapacityAliases::reserve_into(1, &mut slot).unwrap();
        let aliases = slot.as_mut().unwrap();
        let owner_row =
            serde_json::to_value(aliases.shared_arc_owner_data(&owner).unwrap()).unwrap();
        let payload_row =
            serde_json::to_value(aliases.shared_backing_data(owner.as_ref()).unwrap()).unwrap();
        assert_eq!(owner_row, payload_row);
        assert!(payload_row.get("identity").is_none());
        assert_eq!(aliases.identities.len(), 1);
    }
}

#[cfg(test)]
mod borrowed_identity17_tests {
    use super::*;

    #[test]
    fn original_borrowed_input_keeps_its_shared_group_without_address_or_credit() {
        let owner = Rc::new(17u64);
        let independent = Rc::new(17u64);
        let mut slot = None;
        OriginalRestoredOwnerCapacityAliases::reserve_into(1, &mut slot).unwrap();
        let bank = slot.as_mut().unwrap();
        let shared = serde_json::to_value(bank.shared_owner_data(&owner).unwrap()).unwrap();
        let borrowed =
            serde_json::to_value(bank.borrowed_identity_data(Rc::as_ptr(&owner)).unwrap()).unwrap();

        assert_eq!(borrowed["kind"], "borrowed");
        assert_eq!(borrowed["shared_group"], shared["shared_group"]);
        assert_eq!(borrowed["length"], 1);
        assert_eq!(borrowed["capacity"], serde_json::Value::Null);
        assert_eq!(borrowed["element_bytes"], size_of::<u64>());
        assert_eq!(borrowed["alignment"], align_of::<u64>());
        assert!(borrowed.get("identity").is_none());

        let retained = bank.allocated_bytes().unwrap();
        assert!(matches!(
            bank.borrowed_identity_data(Rc::as_ptr(&independent)),
            Err(RuntimeError::ResourceLimit)
        ));
        assert_eq!(bank.allocated_bytes().unwrap(), retained);
        let null = serde_json::to_value(
            bank.borrowed_identity_data(std::ptr::null::<u64>())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(null["shared_group"], serde_json::Value::Null);
        assert_eq!(null["length"], 0);
        assert_eq!(bank.identities.len(), 1);
    }
}
