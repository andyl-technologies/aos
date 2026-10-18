//! Checks the genuine coordinator-state participant's unchanged passive cursor.
//!
//! The Host owns common queues through the whole Runtime. It has no native
//! input or output lane, so its own producer cursor stays at activation while
//! the three native owners advance. This exception never hides queued work.

use super::*;
use crate::node_contract::{Lifecycle, NodeRuntime};
use crate::node_scheduling::{SavedBound, SchedulingSnapshot};
use crucible_node_contract::U64;

pub(super) fn validate_host_role_data(
    source: &HostSchedulingSelection,
    runtime: &OriginalLineageRuntimeRecord,
    scheduling: &SchedulingSnapshot,
) -> Result<(), RuntimeError> {
    let node = &source.descriptor.id;
    let owner = &source.owner.owner.id;
    let initial = runtime.source_activation.boundary;
    if source.descriptor.roles.len() != 1
        || source.descriptor.roles[0].as_str() != "coordinator-state"
        || !source.descriptor.ports.is_empty()
        || source.owner.owner.participant_ids.as_slice() != std::slice::from_ref(node)
        || source.binding.compatibility.execution_owner != source.owner.owner
        || source.binding.compatibility.capture_owner != source.owner.owner
        || runtime.operations.iter().any(|row| &row.route.node == node)
        || runtime.inputs.iter().any(|row| &row.node == node)
        || scheduling
            .reservations
            .iter()
            .any(|row| &row.node == node || &row.owner == owner)
        || scheduling
            .input_batches
            .iter()
            .any(|row| &row.node == node || &row.owner == owner)
        || scheduling
            .native_sequences
            .iter()
            .any(|row| &row.endpoint.node_id == node)
        || scheduling
            .external_closed_prefixes
            .iter()
            .any(|row| &row.endpoint.node_id == node)
        || scheduling.pending_deliveries.iter().any(|row| {
            &row.producer == node
                || &row.consumer == node
                || &row.producer_endpoint.node_id == node
                || &row.consumer_endpoint.node_id == node
        })
    {
        return Err(RuntimeError::OutstandingObligations);
    }
    let mut owners = runtime
        .owners
        .iter()
        .filter(|row| &row.identity.owner == owner);
    let retained = owners.next().ok_or(RuntimeError::InvalidReceipt)?;
    let mut positions = scheduling
        .positions
        .iter()
        .filter(|row| &row.owner == owner);
    let position = positions.next().ok_or(RuntimeError::InvalidReceipt)?;
    let mut producers = scheduling.producers.iter().filter(|row| &row.node == node);
    let producer = producers.next().ok_or(RuntimeError::InvalidReceipt)?;
    if owners.next().is_some()
        || positions.next().is_some()
        || producers.next().is_some()
        || retained.lifecycle != Lifecycle::Stopped
        || retained.operation.is_some()
        || retained.identity.incarnation != source.binding.authority.incarnation_id
        || retained.identity.generation != source.binding.authority.owner_generation
        || retained.domains != source.owner.owner.state_domain_ids
        || position.position != initial
        || producer.bound != SavedBound::Unknown
        || producer.closed_prefix != initial
        || producer.next_sequence != Some(U64::new(0))
    {
        return Err(RuntimeError::InvalidReceipt);
    }
    Ok(())
}

impl NodeRuntime {
    /// Checks the passive Host role beside this same actual runtime allocation.
    ///
    /// The source's private attachment authenticates the actual factory node and
    /// common scheduler. The caller must supply snapshots just read from this
    /// runtime under the same unchanged eligible loan; decoded facts alone never
    /// establish native closed prefixes or a safe point.
    ///
    /// # Errors
    /// Refuses foreign attachment, changed Host identity or a Host operation,
    /// input, output, pending delivery, advanced cursor or altered initial bound.
    pub(crate) fn authenticate_restored17_host_role_data(
        &self,
        source: &HostSchedulingSource,
        runtime: &OriginalLineageRuntimeRecord,
        scheduling: &SchedulingSnapshot,
    ) -> Result<(), RuntimeError> {
        self.authenticate_host_scheduling_source(source)?;
        host_role::validate_host_role_data(source.selection(), runtime, scheduling)?;
        self.authenticate_host_scheduling_source(source)
    }
}

#[cfg(test)]
mod tests {
    // These are inert role-geometry controls; they issue no live capture loan.
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::node_contract::{OwnerIdentity, SavedRuntimeActivation, SavedRuntimeOwner};
    use crate::node_scheduling::{SavedOwner, SavedPosition, SavedProducer};
    use crucible_node_contract::{Phase, Position};

    fn passive_host() -> (
        HostSchedulingSelection,
        OriginalLineageRuntimeRecord,
        SchedulingSnapshot,
    ) {
        let owner = super::super::super::tests::source_owner();
        let source = owner.source();
        let selected = source.selection().clone();
        let initial = Position::new(0.into(), 0.into(), Phase::BoundaryControl);
        let identity = OwnerIdentity {
            owner: selected.owner.owner.id.clone(),
            incarnation: selected.binding.authority.incarnation_id.clone(),
            generation: selected.binding.authority.owner_generation,
        };
        let runtime = OriginalLineageRuntimeRecord {
            schema_version: 7,
            source_activation: SavedRuntimeActivation {
                generation: 1.into(),
                activation_id: Id::new("actual-role-data").unwrap(),
                world_binding_hash: source.world().clone(),
                owners: vec![identity.clone()],
                boundary: initial,
            },
            capture_cut: Position::new(9.into(), 0.into(), Phase::BoundaryControl),
            capture_ordinal: 17.into(),
            owners: vec![SavedRuntimeOwner {
                identity: identity.clone(),
                lifecycle: Lifecycle::Stopped,
                operation: None,
                domains: selected.owner.owner.state_domain_ids.clone(),
            }],
            operations: vec![],
            inputs: vec![],
        };
        let scheduling = SchedulingSnapshot {
            schema_version: 1,
            original_epochs: None,
            ordering_profile: "superdense-v1".into(),
            world_binding_hash: source.world().clone(),
            source_activation_id: runtime.source_activation.activation_id.clone(),
            source_generation: 1.into(),
            source_boundary: initial,
            capture_cut: runtime.capture_cut,
            capture_ordinal: runtime.capture_ordinal,
            source_owners: vec![SavedOwner {
                owner: identity.owner.clone(),
                incarnation: identity.incarnation,
                generation: identity.generation,
            }],
            maximum_microsteps: 64.into(),
            positions: vec![SavedPosition {
                owner: identity.owner,
                position: initial,
            }],
            producers: vec![SavedProducer {
                node: selected.descriptor.id.clone(),
                bound: SavedBound::Unknown,
                closed_prefix: initial,
                next_sequence: Some(0.into()),
            }],
            native_sequences: vec![],
            external_closed_prefixes: vec![],
            payload_objects: vec![],
            pending_deliveries: vec![],
            used_operations: vec![],
            reservations: vec![],
            input_batches: vec![],
            used_input_batches: vec![],
        };
        (selected, runtime, scheduling)
    }

    #[test]
    fn passive_host_keeps_unknown_initial_cursor_at_later_world_cut() {
        let (selection, runtime, scheduling) = passive_host();
        assert_ne!(scheduling.capture_cut, scheduling.positions[0].position);
        assert!(validate_host_role_data(&selection, &runtime, &scheduling).is_ok());

        let mut changed = scheduling.clone();
        changed.positions[0].position = scheduling.capture_cut;
        assert!(validate_host_role_data(&selection, &runtime, &changed).is_err());
        assert_eq!(scheduling.producers[0].bound, SavedBound::Unknown);
        assert_eq!(scheduling.producers[0].next_sequence, Some(0.into()));
    }

    #[test]
    fn passive_host_exception_refuses_output_claims_and_used_native_sequence() {
        let (selection, runtime, scheduling) = passive_host();
        let mut changed = scheduling.clone();
        changed.producers[0].bound = SavedBound::AfterInstant { time_ps: 9.into() };
        assert!(validate_host_role_data(&selection, &runtime, &changed).is_err());

        changed = scheduling.clone();
        changed.producers[0].next_sequence = Some(1.into());
        assert!(validate_host_role_data(&selection, &runtime, &changed).is_err());

        changed = scheduling;
        changed
            .native_sequences
            .push(crate::node_scheduling::SavedNativeSequence {
                endpoint: crucible_node_contract::Endpoint {
                    node_id: selection.descriptor.id.clone(),
                    port_id: Id::new("unexpected-port").unwrap(),
                    lane_id: Id::new("unexpected-lane").unwrap(),
                },
                last_sequence: 0.into(),
            });
        assert!(validate_host_role_data(&selection, &runtime, &changed).is_err());
    }

    #[test]
    fn passive_host_exception_refuses_queued_delivery_and_owned_control() {
        let (selection, mut runtime, mut scheduling) = passive_host();
        runtime.owners[0].operation = Some(Id::new("pending-host-control").unwrap());
        assert!(validate_host_role_data(&selection, &runtime, &scheduling).is_err());
        runtime.owners[0].operation = None;

        let endpoint = crucible_node_contract::Endpoint {
            node_id: selection.descriptor.id.clone(),
            port_id: Id::new("unexpected-port").unwrap(),
            lane_id: Id::new("unexpected-lane").unwrap(),
        };
        let body = canonical::content_ref(b"actual-data", "application/octet-stream").unwrap();
        scheduling
            .pending_deliveries
            .push(crate::node_scheduling::event::Delivery {
                connection_id: None,
                connection_policy_ref: None,
                external_root: None,
                provenance_ref: body.clone(),
                publication_id: Id::new("unexpected-publication").unwrap(),
                producer: Id::new("native-producer").unwrap(),
                consumer: selection.descriptor.id.clone(),
                producer_endpoint: endpoint.clone(),
                consumer_endpoint: endpoint,
                source_sequence: 0.into(),
                native_sequence: 0.into(),
                evaluation: None,
                causal_parents: vec![],
                publication: Position::new(8.into(), 0.into(), Phase::Publication),
                delivery: Position::new(8.into(), 0.into(), Phase::Delivery),
                payload: body,
            });
        assert!(validate_host_role_data(&selection, &runtime, &scheduling).is_err());
        assert_eq!(scheduling.pending_deliveries.len(), 1);
    }
}
