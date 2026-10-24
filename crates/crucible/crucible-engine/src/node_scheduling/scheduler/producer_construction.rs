//! Prices the real no-input scheduler reservation before constructing its grant.
//!
//! This is an ownership observation, not a preview permission. The selected
//! caller still invokes ordinary `admit_exact` and authenticates its real grant.
//! Unknown inputs, pending deliveries and shared-owner input routes refuse.

use super::*;
use crate::node_contract::{NodeRuntime, RuntimeError};
use std::mem::{align_of, size_of};

impl CausalScheduler {
    pub(crate) fn original_restored_producer_grant_construction_data(
        &self,
        node: &Id,
        operation: &Id,
        maximum: usize,
    ) -> Result<(usize, usize), RuntimeError> {
        let owner = self
            .node_owners
            .get(node)
            .ok_or(RuntimeError::UnknownNode)?;
        let schedule = self.owners.get(owner).ok_or(RuntimeError::UnknownNode)?;
        if !matches!(schedule.policy, ExecutionPolicy::Exact { .. })
            || !schedule.inputs.is_empty()
            || self.input_batches.contains_key(owner)
            || schedule.reserved.is_some()
            || self
                .pending
                .values()
                .any(|delivery| self.node_owners.get(&delivery.consumer) == Some(owner))
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        if self.used_operations.contains(operation) {
            return Err(RuntimeError::DuplicateOperation);
        }
        if self.used_operations.len() >= crucible_node_format::MAX_ARRAY_ELEMENTS {
            return Err(RuntimeError::ResourceLimit);
        }
        let map_count = self
            .operations
            .len()
            .checked_add(1)
            .ok_or(RuntimeError::ResourceLimit)?;
        let set_count = self
            .used_operations
            .len()
            .checked_add(1)
            .ok_or(RuntimeError::ResourceLimit)?;
        // reserve retains three distinct operation keys (reserved, lifetime set,
        // reservation map), one node and one owner. Existing capacities remain
        // in the raw owner census beside these additional requested banks.
        let map = NodeRuntime::capture_protocol_tree_storage(
            1,
            map_count,
            size_of::<(Id, Reservation)>(),
            align_of::<(Id, Reservation)>(),
            maximum,
        )?;
        let set = NodeRuntime::capture_protocol_tree_storage(
            1,
            set_count,
            size_of::<Id>(),
            align_of::<Id>(),
            maximum,
        )?;
        let retained = operation
            .allocated_capacity()
            .checked_mul(3)
            .and_then(|bytes| bytes.checked_add(node.allocated_capacity()))
            .and_then(|bytes| bytes.checked_add(owner.allocated_capacity()))
            .and_then(|bytes| bytes.checked_add(map))
            .and_then(|bytes| bytes.checked_add(set))
            .filter(|bytes| *bytes <= maximum)
            .ok_or(RuntimeError::ResourceLimit)?;
        // admit_exact holds its owner clone while exact_limit makes another.
        // reserve's third owner is moved into Reservation and counted above.
        let transient = owner
            .allocated_capacity()
            .checked_mul(2)
            .filter(|bytes| *bytes <= maximum)
            .ok_or(RuntimeError::ResourceLimit)?;
        Ok((retained, transient))
    }

    pub(crate) fn original_restored_producer_grant_construction_counter_scratch_data() -> usize {
        size_of::<&Self>()
            + size_of::<&Id>() * 3
            + size_of::<Option<&Id>>()
            + size_of::<Option<&OwnerSchedule>>()
            + size_of::<Result<&Id, RuntimeError>>()
            + size_of::<Result<&OwnerSchedule, RuntimeError>>()
            + size_of::<
                std::collections::btree_map::Values<
                    'static,
                    crucible_node_format::EventKey,
                    super::super::event::Delivery,
                >,
            >()
            + size_of::<&super::super::event::Delivery>()
            + size_of::<(usize, usize)>()
            + size_of::<Result<(usize, usize), RuntimeError>>()
            + size_of::<Result<usize, RuntimeError>>()
            + size_of::<Result<(), RuntimeError>>()
            + size_of::<Option<usize>>()
            + size_of::<Id>() * 2
            + size_of::<ExecutionAdmission>()
            + size_of::<Result<ExecutionAdmission, SchedulingError>>()
            + size_of::<OperationRequest>()
            + size_of::<ExactPermission>()
            + size_of::<Reservation>()
            + size_of::<Result<Position, SchedulingError>>()
            + size_of::<Result<(Position, ExactBoundaryPolicy), SchedulingError>>()
            + size_of::<Option<Id>>()
    }
}
