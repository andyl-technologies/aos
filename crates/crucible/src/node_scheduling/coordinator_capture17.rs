//! Checks a known whole-world causal boundary without executing pending work.
//!
//! This first closed17 path captures equal actual owner coordinates. Pending
//! deliveries at or after the cut remain modeled queue state; anything earlier
//! requires genuine ordinary Input/Reactive progression before Capture.

use super::{CausalScheduler, OutputBound};
use crate::node_contract::RuntimeError;
use crucible_node_contract::{Position, Validate};

impl CausalScheduler {
    pub(crate) fn authenticate_coordinator17_capture_boundary_data(
        &self,
        cut: Position,
        host_node: &crucible_node_contract::Id,
        host_owner: &crucible_node_contract::Id,
    ) -> Result<(), RuntimeError> {
        cut.validate().map_err(|_| RuntimeError::InvalidReceipt)?;
        if cut.microstep > self.maximum_microsteps {
            return Err(RuntimeError::InvalidReceipt);
        }
        // The attached Host node has no executable/publication ports. Its
        // coordinator state is captured directly, not advanced by a fake run.
        if self.node_owners.get(host_node) != Some(host_owner)
            || self
                .node_owners
                .iter()
                .any(|(node, owner)| node != host_node && owner == host_owner)
            || self
                .output_endpoints
                .keys()
                .any(|endpoint| &endpoint.node_id == host_node)
            || self
                .pending
                .values()
                .any(|delivery| &delivery.consumer == host_node || &delivery.producer == host_node)
            || self.restored_epochs.is_some()
            || self.owners.is_empty()
            || !self.operations.is_empty()
            || !self.input_batches.is_empty()
            || self.owners.iter().any(|(id, owner)| {
                owner.reserved.is_some()
                    || if id == host_owner {
                        owner.cursor != self.activation.record().boundary
                    } else {
                        owner.cursor != cut
                    }
            })
            || !matches!(self.bounds.get(host_node), Some(OutputBound::Unknown))
            || self.closed_prefixes.get(host_node) != Some(&self.activation.record().boundary)
            || self.sequences.next(host_node) != Some(crucible_node_contract::U64::new(0))
            || self
                .native_sequences
                .keys()
                .any(|endpoint| &endpoint.node_id == host_node)
            || self
                .pending
                .values()
                .any(|delivery| delivery.delivery < cut)
            || self.closed_prefixes.len() != self.bounds.len()
            || self
                .closed_prefixes
                .iter()
                .any(|(node, prefix)| node != host_node && *prefix < cut)
            || self
                .external_closed_prefixes
                .values()
                .any(|prefix| *prefix < cut)
            || self.bounds.iter().any(|(node, bound)| {
                node != host_node
                    && match bound {
                        OutputBound::Unknown => true,
                        OutputBound::At(position) => *position < cut,
                        OutputBound::AfterInstant(time) => *time < cut.time_ps,
                    }
            })
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        Ok(())
    }
}

impl CausalScheduler {
    pub(crate) fn coordinator17_capture_boundary_counter_scratch_data() -> usize {
        use std::mem::size_of;
        size_of::<&Self>()
            + size_of::<Position>()
            + size_of::<
                std::collections::btree_map::Values<
                    'static,
                    crucible_node_contract::Id,
                    super::OwnerSchedule,
                >,
            >()
            + size_of::<
                std::collections::btree_map::Values<
                    'static,
                    crucible_node_contract::EventKey,
                    super::Delivery,
                >,
            >()
            + size_of::<
                std::collections::btree_map::Values<'static, crucible_node_contract::Id, Position>,
            >()
            + size_of::<
                std::collections::btree_map::Values<
                    'static,
                    crucible_node_contract::Endpoint,
                    Position,
                >,
            >()
            + size_of::<
                std::collections::btree_map::Values<
                    'static,
                    crucible_node_contract::Id,
                    OutputBound,
                >,
            >()
            + size_of::<Result<(), RuntimeError>>()
            + size_of::<Result<(), crucible_node_contract::ContractError>>()
    }
}
