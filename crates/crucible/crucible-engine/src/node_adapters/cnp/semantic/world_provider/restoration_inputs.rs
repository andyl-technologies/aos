//! Moves actual collecting peers and their ticketed Host into a retained preparation.
//!
//! This callback-free move does not admit a graph or create restoration rights.
//! The caller first admits its whole constructor row, then passes the result to
//! the real archive source's complete-restoration constructor.

use super::*;
use crate::node_contract::{NodeRuntime, PreparedHostSchedulingNode};
use std::mem::size_of;

impl CnpSemanticConformanceNode {
    /// Quotes only the new four-node pointer bank, Boxes and activation clone.
    ///
    /// Existing node metadata, graph, archive, Source and custody backing remain
    /// independently owned and counted by the enclosing installed holder.
    ///
    /// # Errors
    /// Refuses another roster, overflow or demand above the supplied maximum.
    pub fn original_restoration_prepared_construction_storage_data(
        activation: &ActivationRecord,
        maximum: usize,
    ) -> Result<(usize, usize, usize), RuntimeError> {
        if activation.owners.len() != 4 {
            return Err(RuntimeError::ForeignAuthority);
        }
        let activation_bytes = NodeRuntime::capture_activation_storage_data(activation, maximum)?;
        let retained = [
            size_of::<PreparedRealization>(),
            4 * size_of::<Box<dyn SimulationNode>>(),
            3 * size_of::<Self>(),
            size_of::<PreparedHostSchedulingNode>(),
            activation_bytes,
        ]
        .into_iter()
        .try_fold(0usize, |total, bytes| {
            total
                .checked_add(bytes)
                .filter(|next| *next <= maximum)
                .ok_or(RuntimeError::ResourceLimit)
        })?;
        let scratch = Self::original_restoration_prepared_counter_scratch_data();
        retained
            .checked_add(scratch)
            .filter(|total| *total <= maximum)
            .ok_or(RuntimeError::ResourceLimit)?;
        Ok((retained, 0, scratch))
    }

    /// Names the exact fixed move, quote and output views before construction.
    pub fn original_restoration_prepared_counter_scratch_data() -> usize {
        size_of::<[Option<Self>; 3]>()
            + size_of::<&mut [Option<Self>; 3]>()
            + size_of::<Option<PreparedHostSchedulingNode>>()
            + size_of::<&mut Option<PreparedHostSchedulingNode>>()
            + size_of::<Vec<Box<dyn SimulationNode>>>()
            + size_of::<&mut Vec<Box<dyn SimulationNode>>>()
            + size_of::<Option<Box<dyn RuntimeCustodySlot>>>()
            + size_of::<&mut Option<Box<dyn RuntimeCustodySlot>>>()
            + size_of::<Option<PreparedRealization>>()
            + size_of::<&mut Option<PreparedRealization>>()
            + size_of::<(
                [Option<Self>; 3],
                Option<PreparedHostSchedulingNode>,
                Option<Box<dyn RuntimeCustodySlot>>,
            )>()
            + size_of::<&ActivationRecord>()
            + size_of::<ActivationRecord>()
            + size_of::<RuntimeLimits>()
            + size_of::<[usize; 5]>()
            + size_of::<std::array::IntoIter<usize, 5>>()
            + 3 * size_of::<usize>()
            + size_of::<Option<usize>>()
            + size_of::<std::slice::Iter<'_, Option<Self>>>()
            + size_of::<&Option<Self>>()
            + size_of::<Result<usize, RuntimeError>>()
            + size_of::<(usize, usize, usize)>()
            + size_of::<Result<(usize, usize, usize), RuntimeError>>()
            + size_of::<Result<(), RuntimeError>>()
    }

    /// Moves all four genuine inactive nodes into the caller's retained output.
    ///
    /// The pointer bank must already reserve exactly four slots. Missing inputs
    /// and occupied output refuse before any move. The complete archive/runtime
    /// constructor remains responsible for the original source, graph and ticket
    /// correspondence; this method creates no Ready or restoration permission.
    ///
    /// # Errors
    /// Refuses incomplete input owners, another finite roster, a nonempty or
    /// differently sized bank, or occupied output without dropping originals.
    // crucible-lint: allow rust-allow -- Each original has a distinct failure-retaining slot.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_original_restoration_inputs_into(
        nodes: &mut [Option<Self>; 3],
        host: &mut Option<PreparedHostSchedulingNode>,
        native: &mut Vec<Box<dyn SimulationNode>>,
        slot: &mut Option<Box<dyn RuntimeCustodySlot>>,
        activation: &ActivationRecord,
        limits: RuntimeLimits,
        output: &mut Option<PreparedRealization>,
    ) -> Result<(), RuntimeError> {
        if output.is_some()
            || !native.is_empty()
            || native.capacity() != 4
            || activation.owners.len() != 4
            || nodes.iter().any(Option::is_none)
            || host.is_none()
            || slot.is_none()
        {
            return Err(RuntimeError::OutstandingObligations);
        }

        // No callback or fallible operation separates the aggregate take from
        // its destination. The fallback restores all originals if any is absent.
        let original_nodes = std::mem::replace(nodes, std::array::from_fn(|_| None));
        match (original_nodes, host.take(), slot.take()) {
            ([Some(a), Some(b), Some(c)], Some(original_host), Some(original_slot)) => {
                native.push(Box::new(original_host));
                native.push(Box::new(a.0));
                native.push(Box::new(b.0));
                native.push(Box::new(c.0));
                *output = Some(PreparedRealization::new(
                    std::mem::take(native),
                    activation.clone(),
                    limits,
                    original_slot,
                ));
                Ok(())
            }
            (original_nodes, original_host, original_slot) => {
                *nodes = original_nodes;
                *host = original_host;
                *slot = original_slot;
                Err(RuntimeError::OwnerUnavailable)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node_contract::OwnerIdentity;
    use crucible_node_format::{Id, Phase, Position, U64, canonical};

    // These are geometry records only. No graph, native node, ticket or Window
    // can be created by this fixture, including its successful numeric quote.
    fn activation() -> ActivationRecord {
        ActivationRecord {
            generation: U64::new(1),
            activation_id: Id::new("restoration-prepared-geometry").unwrap(),
            world_binding_hash: canonical::hash("restoration-prepared-geometry", b"world").unwrap(),
            owners: (0..4)
                .map(|index| OwnerIdentity {
                    owner: Id::new(format!("geometry-owner-{index}")).unwrap(),
                    incarnation: Id::new(format!("geometry-incarnation-{index}")).unwrap(),
                    generation: U64::new(1),
                })
                .collect(),
            boundary: Position::new(U64::new(0), U64::new(0), Phase::BoundaryControl),
        }
    }

    #[test]
    fn prepared_geometry_exact_and_one_short_preserve_actual_activation_spares() {
        let mut activation = activation();
        activation.owners.reserve_exact(7);
        let capacity = activation.owners.capacity();
        let row =
            CnpSemanticConformanceNode::original_restoration_prepared_construction_storage_data(
                &activation,
                usize::MAX,
            )
            .unwrap();
        let peak = row
            .0
            .checked_add(row.1)
            .and_then(|bytes| bytes.checked_add(row.2))
            .unwrap();
        assert_eq!(
            CnpSemanticConformanceNode::original_restoration_prepared_construction_storage_data(
                &activation,
                peak,
            )
            .unwrap(),
            row
        );
        assert!(
            CnpSemanticConformanceNode::original_restoration_prepared_construction_storage_data(
                &activation,
                peak - 1,
            )
            .is_err()
        );
        assert_eq!(activation.owners.capacity(), capacity);
        activation.owners.pop();
        assert!(
            CnpSemanticConformanceNode::original_restoration_prepared_construction_storage_data(
                &activation,
                usize::MAX,
            )
            .is_err()
        );
    }

    #[test]
    fn absent_native_owners_cannot_construct_a_prepared_runtime_from_geometry() {
        let activation = activation();
        let mut nodes = std::array::from_fn(|_| None);
        let mut host = None;
        let mut native = Vec::with_capacity(4);
        let capacity = native.capacity();
        let mut slot = None;
        let mut output = None;
        let limits = RuntimeLimits {
            maximum_nodes: 4,
            maximum_owners: 4,
            maximum_operations: 1,
            maximum_retained_outputs: 1,
        };

        assert!(
            CnpSemanticConformanceNode::prepare_original_restoration_inputs_into(
                &mut nodes,
                &mut host,
                &mut native,
                &mut slot,
                &activation,
                limits,
                &mut output,
            )
            .is_err()
        );

        assert!(nodes.iter().all(Option::is_none));
        assert!(host.is_none());
        assert!(native.is_empty());
        assert_eq!(native.capacity(), capacity);
        assert!(slot.is_none());
        assert!(output.is_none());
    }
}
