//! Complete live stopped scope that may retain future events and deliveries.

use std::collections::{BTreeMap, BTreeSet};

use crucible_node_contract::{Bytes, Id, Position, U64, canonical};

use super::{CausalScheduler, SchedulingError};
use crate::node_contract::{NativeConditionStopInventory, RuntimeError};

impl CausalScheduler {
    pub(crate) fn condition_identity_available(&self, operation: &Id) -> bool {
        !self.used_operations.contains(operation)
    }

    pub(crate) fn retain_condition_identity(&mut self, operation: Id) -> Result<(), RuntimeError> {
        if !self.used_operations.insert(operation) {
            return Err(RuntimeError::DuplicateOperation);
        }
        Ok(())
    }

    pub(crate) fn condition_stop_scope(
        &self,
        inventories: &BTreeMap<Id, NativeConditionStopInventory>,
        maximum_bytes: usize,
    ) -> Result<(Position, Bytes), RuntimeError> {
        // This reads custody; it does not settle an input, drop a future event,
        // authorize a grant or infer EOF from physical suspension.
        if self.restored_epochs.is_some()
            || !self.operations.is_empty()
            || !self.external_roots.is_empty()
            || self.owners.values().any(|owner| owner.reserved.is_some())
            || self.input_batches.values().any(|input| {
                input.acknowledgement.is_none()
                    || input.activated_by.is_some()
                    || input.consumed.len() != input.batch.deliveries().len()
            })
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        let expected: BTreeSet<_> = self.node_owners.keys().cloned().collect();
        if inventories.keys().cloned().collect::<BTreeSet<_>>() != expected {
            return Err(RuntimeError::InvalidRoute);
        }
        let cut = inventories
            .values()
            .next()
            .map(|native| native.boundary)
            .ok_or(RuntimeError::InvalidTiming)?;
        for (node, native) in inventories {
            let owner = self
                .node_owners
                .get(node)
                .ok_or(RuntimeError::UnknownNode)?;
            if native.boundary != cut
                || self.owners.get(owner).map(|owner| owner.cursor) != Some(cut)
            {
                return Err(RuntimeError::InvalidTiming);
            }
        }
        // Future queues remain exactly represented. An already due delivery
        // cannot be hidden behind a condition marker or a later global label.
        if self
            .pending
            .values()
            .any(|delivery| delivery.delivery < cut)
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        self.condition_scope_credit(maximum_bytes)?;
        let snapshot = self
            .snapshot(cut, U64::new(0))
            .map_err(|error| RuntimeError::SchedulerRefused(error.to_string()))?;
        if snapshot.schema_version != 1 || snapshot.original_epochs.is_some() {
            return Err(RuntimeError::UnsupportedFacet);
        }
        let mut state = serde_json::to_value(snapshot).map_err(|_| RuntimeError::InvalidReceipt)?;
        let object = state.as_object_mut().ok_or(RuntimeError::InvalidReceipt)?;
        object.remove("capture_ordinal");
        object.remove("schema_version");
        object.insert(
            "format".into(),
            "crucible.condition-stop-coordinator".into(),
        );
        object.insert("version".into(), 1.into());
        let bytes = canonical::canonical_json(&state).map_err(|_| RuntimeError::InvalidReceipt)?;
        if bytes.len() > maximum_bytes {
            return Err(RuntimeError::ResourceLimit);
        }
        Ok((cut, Bytes::new(bytes)))
    }

    fn condition_scope_credit(&self, maximum_bytes: usize) -> Result<(), RuntimeError> {
        let rows = self
            .owners
            .len()
            .saturating_add(self.bounds.len())
            .saturating_add(self.native_sequences.len())
            .saturating_add(self.used_operations.len())
            .saturating_add(self.used_input_batches.len())
            .saturating_add(self.pending.len())
            .saturating_add(self.input_batches.values().fold(0usize, |count, input| {
                count
                    .saturating_add(1)
                    .saturating_add(input.batch.deliveries.len())
                    .saturating_add(input.consumed.len())
            }));
        let payload = self
            .payloads
            .values()
            .chain(
                self.input_batches
                    .values()
                    .flat_map(|input| input.batch.payloads.iter().map(|payload| &payload.bytes)),
            )
            .try_fold(0usize, |count, bytes| count.checked_add(bytes.len()))
            .ok_or(RuntimeError::ResourceLimit)?;
        let estimate = rows
            .checked_mul(4096)
            .and_then(|metadata| {
                payload
                    .checked_mul(4)
                    .and_then(|payload| metadata.checked_add(payload))
            })
            .ok_or(RuntimeError::ResourceLimit)?;
        if maximum_bytes == 0 || rows > 65_536 || estimate > maximum_bytes {
            return Err(RuntimeError::ResourceLimit);
        }
        Ok(())
    }
}

impl CausalScheduler {
    /// Reports actual retained, acknowledged native input-cut custody.
    ///
    /// This read creates no staging or execution permission and permits no
    /// substitute batch while an original partially consumed cut remains owned.
    ///
    /// # Errors
    /// Refuses an unknown owner or an unsettled/active input cut.
    pub fn condition_input_cut_retained(&self, node: &Id) -> Result<bool, SchedulingError> {
        let owner = self.owner_id(node)?;
        match self.input_batches.get(owner) {
            None => Ok(false),
            Some(state) if state.acknowledgement.is_some() && state.activated_by.is_none() => {
                Ok(true)
            }
            Some(_) => Err(SchedulingError::OwnerBusy),
        }
    }
}
