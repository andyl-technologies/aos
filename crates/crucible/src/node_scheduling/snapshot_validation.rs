//! Structural and admitted-policy checks for complete saved continuation.

use super::*;

pub(super) fn validate_snapshot(
    graph: &AdmittedGraph,
    target: &ActivationRecord,
    snapshot: &SchedulingSnapshot,
) -> Result<(), SchedulingError> {
    validate_saved_profile(graph, snapshot, Some(&target.owners))?;
    if snapshot.world_binding_hash != target.world_binding_hash
        || target.generation <= snapshot.source_generation
        || target.activation_id == snapshot.source_activation_id
        || target.boundary != snapshot.capture_cut
    {
        return Err(SchedulingError::InvalidSnapshot);
    }
    for source in &snapshot.source_owners {
        let fresh = target
            .owners
            .iter()
            .find(|owner| owner.owner == source.owner)
            .ok_or(SchedulingError::InvalidSnapshot)?;
        if source.generation.get() == 0
            || fresh.generation <= source.generation
            || fresh.incarnation == source.incarnation
        {
            return Err(SchedulingError::ForeignActivation);
        }
    }
    Ok(())
}

/// Checks recorded source continuation against immutable admitted compatibility.
///
/// Historical source provenance is authenticated separately from fresh live
/// graph incarnations. This structural check never issues native authority.
///
/// # Errors
/// Refuses malformed or incompatible snapshots, incomplete owner/producer
/// rosters, invalid causal positions, contradictory original FIFO inventory,
/// exceeded finite custody limits, and unqualified connection conversions.
pub fn validate_saved_source(
    graph: &AdmittedGraph,
    snapshot: &SchedulingSnapshot,
) -> Result<(), SchedulingError> {
    validate_saved_profile(graph, snapshot, None)
}

fn validate_saved_profile(
    graph: &AdmittedGraph,
    snapshot: &SchedulingSnapshot,
    graph_owners: Option<&[crate::node_contract::OwnerIdentity]>,
) -> Result<(), SchedulingError> {
    validate_structure(snapshot)?;
    if &snapshot.world_binding_hash != graph.world_binding_hash()
        || snapshot.maximum_microsteps != graph.coordinator_policy().maximum_microsteps_per_instant
        || snapshot.capture_cut < snapshot.source_boundary
    {
        return Err(SchedulingError::InvalidSnapshot);
    }
    let owner_ids: BTreeSet<_> = graph.owners().map(|owner| owner.owner.id.clone()).collect();
    if snapshot
        .source_owners
        .iter()
        .map(|owner| owner.owner.clone())
        .collect::<BTreeSet<_>>()
        != owner_ids
        || graph_owners.is_some_and(|owners| {
            owners
                .iter()
                .map(|owner| owner.owner.clone())
                .collect::<BTreeSet<_>>()
                != owner_ids
                || owners.len() != owner_ids.len()
        })
        || snapshot
            .source_owners
            .iter()
            .any(|source| source.generation.get() == 0)
    {
        return Err(SchedulingError::InvalidSnapshot);
    }

    let mut execution_owners = BTreeMap::new();
    let mut owner_contracts: BTreeMap<Id, (QuantumGrid, ExecutionPolicy)> = BTreeMap::new();
    for node in graph.node_ids() {
        let binding = graph
            .binding(node)
            .ok_or(SchedulingError::InvalidSnapshot)?;
        let contract = &binding.compatibility.operating_contract;
        let policy = graph
            .operating_policy(node)
            .ok_or(SchedulingError::UnsupportedMode)?;
        let grid = match (policy, contract.mode) {
            (ExecutionPolicy::Exact { .. }, OperatingMode::Exact) => QuantumGrid::new(
                contract
                    .resolution_ps
                    .ok_or(SchedulingError::UnsupportedMode)?,
                contract.phase_ps.ok_or(SchedulingError::UnsupportedMode)?,
            )?,
            (
                ExecutionPolicy::Quantized {
                    quantum_ps,
                    phase_ps,
                    ..
                },
                OperatingMode::Quantized,
            ) => QuantumGrid::new(*quantum_ps, *phase_ps)?,
            _ => return Err(SchedulingError::UnsupportedMode),
        };
        let owner = &binding.compatibility.execution_owner.id;
        if owner_contracts
            .get(owner)
            .is_some_and(|saved| saved != &(grid, policy.clone()))
        {
            return Err(SchedulingError::UnsupportedMode);
        }
        owner_contracts.insert(owner.clone(), (grid, policy.clone()));
        execution_owners.insert(node.clone(), owner.clone());
        if let Some(graph_owners) = graph_owners {
            let live = graph_owners
                .iter()
                .find(|live| &live.owner == owner)
                .ok_or(SchedulingError::ForeignActivation)?;
            if live.incarnation != binding.authority.incarnation_id
                || live.generation != binding.authority.owner_generation
            {
                return Err(SchedulingError::ForeignActivation);
            }
        }
    }
    if snapshot
        .positions
        .iter()
        .map(|saved| saved.owner.clone())
        .collect::<BTreeSet<_>>()
        != owner_contracts.keys().cloned().collect()
        || snapshot
            .producers
            .iter()
            .map(|saved| saved.node.clone())
            .collect::<BTreeSet<_>>()
            != execution_owners.keys().cloned().collect()
    {
        return Err(SchedulingError::InvalidSnapshot);
    }
    let positions: BTreeMap<_, _> = snapshot
        .positions
        .iter()
        .map(|saved| (saved.owner.clone(), saved.position))
        .collect();
    for saved in &snapshot.positions {
        validate_position(saved.position, snapshot.maximum_microsteps)?;
        if saved.position < snapshot.source_boundary {
            return Err(SchedulingError::InvalidSnapshot);
        }
        let (grid, policy) = &owner_contracts[&saved.owner];
        if matches!(policy, ExecutionPolicy::Quantized { .. })
            && !grid.contains(saved.position.time_ps)
        {
            return Err(SchedulingError::InvalidSnapshot);
        }
    }
    let sequences: BTreeMap<_, _> = snapshot
        .producers
        .iter()
        .map(|producer| (producer.node.clone(), producer.next_sequence))
        .collect();
    for producer in &snapshot.producers {
        if let SavedBound::At { position } = producer.bound {
            validate_position(position, snapshot.maximum_microsteps)?;
            if position.phase != Phase::Publication {
                return Err(SchedulingError::InvalidSnapshot);
            }
        }
    }
    let mut pending_sequences = BTreeSet::new();
    let payloads: BTreeMap<_, _> = snapshot
        .payload_objects
        .iter()
        .map(|payload| (payload.reference.clone(), payload))
        .collect();
    let maximum_bytes = graph
        .world()
        .connections
        .iter()
        .try_fold(0u64, |total, connection| {
            let capacity = graph
                .connection_policy(&connection.id)
                .ok_or(SchedulingError::InvalidSnapshot)?
                .maximum_pending_bytes
                .get();
            total
                .checked_add(capacity)
                .ok_or(SchedulingError::InvalidSnapshot)
        })?;
    let maximum_bytes = graph.coordinator_policy().external_inputs.iter().try_fold(
        maximum_bytes,
        |total, endpoint| {
            let policy = graph
                .port_policy(&endpoint.node_id, &endpoint.port_id)
                .and_then(|port| {
                    port.lanes
                        .iter()
                        .find(|lane| lane.lane_id == endpoint.lane_id)
                })
                .ok_or(SchedulingError::InvalidSnapshot)?;
            total
                .checked_add(policy.maximum_pending_bytes.get())
                .ok_or(SchedulingError::InvalidSnapshot)
        },
    )?;
    for prefix in &snapshot.external_closed_prefixes {
        if !graph
            .coordinator_policy()
            .external_inputs
            .contains(&prefix.endpoint)
        {
            return Err(SchedulingError::InvalidSnapshot);
        }
    }
    for endpoint in &graph.coordinator_policy().external_inputs {
        let maximum = graph
            .port_policy(&endpoint.node_id, &endpoint.port_id)
            .and_then(|port| {
                port.lanes
                    .iter()
                    .find(|lane| lane.lane_id == endpoint.lane_id)
            })
            .ok_or(SchedulingError::InvalidSnapshot)?
            .maximum_pending_bytes;
        let bytes = snapshot
            .pending_deliveries
            .iter()
            .filter(|delivery| delivery.external_root.as_ref() == Some(endpoint))
            .try_fold(0u64, |total, delivery| {
                total
                    .checked_add(delivery.payload.length.get())
                    .ok_or(SchedulingError::InvalidSnapshot)
            })?;
        if bytes > maximum.get() {
            return Err(SchedulingError::InvalidSnapshot);
        }
    }
    let payload_bytes = snapshot
        .payload_objects
        .iter()
        .try_fold(0u64, |total, payload| {
            total
                .checked_add(payload.bytes.len() as u64)
                .ok_or(SchedulingError::InvalidSnapshot)
        })?;
    if payload_bytes > maximum_bytes {
        return Err(SchedulingError::InvalidSnapshot);
    }
    for saved in &snapshot.native_sequences {
        let descriptor = graph
            .descriptor(&saved.endpoint.node_id)
            .ok_or(SchedulingError::InvalidSnapshot)?;
        if !descriptor.ports.iter().any(|port| {
            port.id == saved.endpoint.port_id
                && port.lanes.iter().any(|lane| {
                    lane.id == saved.endpoint.lane_id
                        && (lane.direction == crucible_node_contract::Direction::Output
                            || graph
                                .coordinator_policy()
                                .external_inputs
                                .contains(&saved.endpoint))
                })
        }) {
            return Err(SchedulingError::InvalidSnapshot);
        }
    }
    for delivery in &snapshot.pending_deliveries {
        delivery.payload.validate()?;
        delivery.provenance_ref.validate()?;
        if let Some(reference) = &delivery.connection_policy_ref {
            reference.validate()?;
        }
        validate_position(delivery.publication, snapshot.maximum_microsteps)?;
        validate_position(delivery.delivery, snapshot.maximum_microsteps)?;
        let consumer_owner = execution_owners
            .get(&delivery.consumer)
            .ok_or(SchedulingError::InvalidSnapshot)?;
        if delivery.external_root.is_some() {
            validate_external_delivery(graph, delivery, snapshot.maximum_microsteps)?;
            let payload = payloads
                .get(&delivery.payload)
                .ok_or(SchedulingError::InvalidSnapshot)?;
            let native_last = snapshot
                .native_sequences
                .iter()
                .find(|saved| saved.endpoint == delivery.producer_endpoint)
                .ok_or(SchedulingError::InvalidSnapshot)?;
            if delivery.delivery < positions[consumer_owner]
                || delivery.native_sequence > native_last.last_sequence
                || !pending_sequences.insert((delivery.producer.clone(), delivery.source_sequence))
                || sequences[&delivery.producer]
                    .is_some_and(|next| next <= delivery.source_sequence)
                || crucible_node_contract::canonical::content_ref(
                    &payload.bytes,
                    &payload.reference.media_type,
                )? != payload.reference
            {
                return Err(SchedulingError::InvalidSnapshot);
            }
            continue;
        }
        let connection = graph
            .world()
            .connections
            .iter()
            .find(|connection| delivery.connection_id.as_ref() == Some(&connection.id))
            .ok_or(SchedulingError::InvalidSnapshot)?;
        let earliest_arrival = delivery
            .publication
            .time_ps
            .checked_add(connection.minimum_latency_ps)?;
        let policy = graph
            .connection_policy(&connection.id)
            .ok_or(SchedulingError::InvalidSnapshot)?;
        let latency = match policy.delivery {
            crate::node_admission::ConnectionDelivery::Fixed { latency_ps } => latency_ps,
        };
        let (grid, _) = &owner_contracts[consumer_owner];
        let destination_grid = match policy.visibility {
            crate::node_admission::VisibilityConversion::Direct
            | crate::node_admission::VisibilityConversion::PublicationPreserving { .. } => None,
            crate::node_admission::VisibilityConversion::BoundarySampling { .. } => Some(*grid),
            crate::node_admission::VisibilityConversion::Adapter { .. } => {
                return Err(SchedulingError::UnsupportedMode);
            }
        };
        if crate::node_scheduling::event::direct_delivery(
            delivery.publication,
            latency,
            destination_grid,
        )? != delivery.delivery
        {
            return Err(SchedulingError::InvalidSnapshot);
        }
        validate_delivery_lineage(delivery, snapshot.maximum_microsteps)?;
        let native_last = snapshot
            .native_sequences
            .iter()
            .find(|saved| saved.endpoint == connection.producer)
            .ok_or(SchedulingError::InvalidSnapshot)?;
        if delivery.native_sequence > native_last.last_sequence {
            return Err(SchedulingError::InvalidSnapshot);
        }
        let payload = payloads
            .get(&delivery.payload)
            .ok_or(SchedulingError::InvalidSnapshot)?;
        if crucible_node_contract::canonical::content_ref(
            &payload.bytes,
            &delivery.payload.media_type,
        )? != delivery.payload
        {
            return Err(SchedulingError::InvalidSnapshot);
        }
        if !execution_owners.contains_key(&delivery.producer)
            || connection.producer != delivery.producer_endpoint
            || connection.consumer != delivery.consumer_endpoint
            || connection.producer.node_id != delivery.producer
            || connection.consumer.node_id != delivery.consumer
            || delivery.connection_policy_ref.as_ref() != Some(&connection.policy_ref)
            || delivery.delivery.time_ps < earliest_arrival
            || delivery.publication.phase != Phase::Publication
            || delivery.delivery.phase != Phase::Delivery
            || delivery.delivery <= delivery.publication
            || delivery.delivery < positions[consumer_owner]
            || !pending_sequences.insert((delivery.producer.clone(), delivery.source_sequence))
            || sequences[&delivery.producer].is_some_and(|next| next <= delivery.source_sequence)
        {
            return Err(SchedulingError::InvalidSnapshot);
        }
        let (grid, policy) = &owner_contracts[consumer_owner];
        if matches!(policy, ExecutionPolicy::Quantized { .. })
            && !grid.contains(delivery.delivery.time_ps)
        {
            return Err(SchedulingError::InvalidSnapshot);
        }
        if (delivery.delivery.time_ps == delivery.publication.time_ps
            && delivery.delivery.microstep != delivery.publication.microstep)
            || (delivery.delivery.time_ps > delivery.publication.time_ps
                && delivery.delivery.microstep.get() != 0)
        {
            return Err(SchedulingError::InvalidSnapshot);
        }
    }
    let used: BTreeSet<_> = snapshot.used_operations.iter().cloned().collect();
    for connection in &graph.world().connections {
        let policy = graph
            .connection_policy(&connection.id)
            .ok_or(SchedulingError::InvalidSnapshot)?;
        let (count, bytes) = snapshot
            .pending_deliveries
            .iter()
            .filter(|delivery| delivery.connection_id.as_ref() == Some(&connection.id))
            .try_fold((0u64, 0u64), |(count, bytes), delivery| {
                Ok::<_, SchedulingError>((
                    count
                        .checked_add(1)
                        .ok_or(SchedulingError::InvalidSnapshot)?,
                    bytes
                        .checked_add(delivery.payload.length.get())
                        .ok_or(SchedulingError::InvalidSnapshot)?,
                ))
            })?;
        if count > policy.maximum_pending_events.get() || bytes > policy.maximum_pending_bytes.get()
        {
            return Err(SchedulingError::InvalidSnapshot);
        }
    }
    for batch in &snapshot.input_batches {
        if execution_owners.get(&batch.node) != Some(&batch.owner)
            || !snapshot.used_operations.contains(&batch.stage_operation)
            || !snapshot.used_input_batches.contains(&batch.batch)
        {
            return Err(SchedulingError::InvalidSnapshot);
        }
        let binding = graph
            .binding(&batch.node)
            .ok_or(SchedulingError::InvalidSnapshot)?;
        let route: BTreeSet<_> = [
            binding.compatibility.execution_owner.id.clone(),
            binding.compatibility.capture_owner.id.clone(),
        ]
        .into_iter()
        .collect();
        let expected_owners: Vec<_> = snapshot
            .source_owners
            .iter()
            .filter(|owner| route.contains(&owner.owner))
            .map(|owner| crate::node_contract::OwnerIdentity {
                owner: owner.owner.clone(),
                incarnation: owner.incarnation.clone(),
                generation: owner.generation,
            })
            .collect();
        if batch.owners != expected_owners {
            return Err(SchedulingError::InvalidSnapshot);
        }
        if batch.activated_by.as_ref().is_some_and(|operation| {
            !snapshot.reservations.iter().any(|reservation| {
                &reservation.operation == operation
                    && reservation.owner == batch.owner
                    && reservation.input_batch.as_ref() == Some(&batch.batch)
            })
        }) {
            return Err(SchedulingError::InvalidSnapshot);
        }
        let retained_bytes = batch.payloads.iter().try_fold(0u64, |total, payload| {
            total
                .checked_add(payload.bytes.len() as u64)
                .ok_or(SchedulingError::InvalidSnapshot)
        })?;
        if retained_bytes > maximum_bytes {
            return Err(SchedulingError::InvalidSnapshot);
        }
        for delivery in &batch.deliveries {
            if execution_owners.get(&delivery.consumer) != Some(&batch.owner) {
                return Err(SchedulingError::InvalidSnapshot);
            }
            if delivery.external_root.is_some() {
                validate_external_delivery(graph, delivery, snapshot.maximum_microsteps)?;
                continue;
            }
            let connection = graph
                .world()
                .connections
                .iter()
                .find(|connection| delivery.connection_id.as_ref() == Some(&connection.id))
                .ok_or(SchedulingError::InvalidSnapshot)?;
            let policy = graph
                .connection_policy(&connection.id)
                .ok_or(SchedulingError::InvalidSnapshot)?;
            if connection.producer != delivery.producer_endpoint
                || connection.consumer != delivery.consumer_endpoint
                || connection.producer.node_id != delivery.producer
                || connection.consumer.node_id != delivery.consumer
                || delivery.connection_policy_ref.as_ref() != Some(&connection.policy_ref)
                || delivery.payload.length > policy.maximum_payload_bytes
            {
                return Err(SchedulingError::InvalidSnapshot);
            }
            let crate::node_admission::ConnectionDelivery::Fixed { latency_ps } = policy.delivery;
            let destination_grid = match policy.visibility {
                crate::node_admission::VisibilityConversion::Direct
                | crate::node_admission::VisibilityConversion::PublicationPreserving { .. } => None,
                crate::node_admission::VisibilityConversion::BoundarySampling { .. } => {
                    Some(owner_contracts[&batch.owner].0)
                }
                crate::node_admission::VisibilityConversion::Adapter { .. } => {
                    return Err(SchedulingError::UnsupportedMode);
                }
            };
            if crate::node_scheduling::event::direct_delivery(
                delivery.publication,
                latency_ps,
                destination_grid,
            )? != delivery.delivery
            {
                return Err(SchedulingError::InvalidSnapshot);
            }
        }
        for connection in &graph.world().connections {
            let policy = graph
                .connection_policy(&connection.id)
                .ok_or(SchedulingError::InvalidSnapshot)?;
            let (count, bytes) = batch
                .deliveries
                .iter()
                .filter(|delivery| delivery.connection_id.as_ref() == Some(&connection.id))
                .try_fold((0u64, 0u64), |(count, bytes), delivery| {
                    Ok::<_, SchedulingError>((
                        count
                            .checked_add(1)
                            .ok_or(SchedulingError::InvalidSnapshot)?,
                        bytes
                            .checked_add(delivery.payload.length.get())
                            .ok_or(SchedulingError::InvalidSnapshot)?,
                    ))
                })?;
            if count > policy.maximum_pending_events.get()
                || bytes > policy.maximum_pending_bytes.get()
            {
                return Err(SchedulingError::InvalidSnapshot);
            }
        }
        for endpoint in &graph.coordinator_policy().external_inputs {
            let maximum_bytes = graph
                .port_policy(&endpoint.node_id, &endpoint.port_id)
                .and_then(|port| {
                    port.lanes
                        .iter()
                        .find(|lane| lane.lane_id == endpoint.lane_id)
                })
                .ok_or(SchedulingError::InvalidSnapshot)?
                .maximum_pending_bytes;
            let retained_bytes = batch
                .deliveries
                .iter()
                .filter(|delivery| delivery.external_root.as_ref() == Some(endpoint))
                .try_fold(0u64, |total, delivery| {
                    total
                        .checked_add(delivery.payload.length.get())
                        .ok_or(SchedulingError::InvalidSnapshot)
                })?;
            if retained_bytes > maximum_bytes.get() {
                return Err(SchedulingError::InvalidSnapshot);
            }
        }
        for delivery in &batch.deliveries[batch.consumed.len()..] {
            if !snapshot.pending_deliveries.contains(delivery) {
                return Err(SchedulingError::InvalidSnapshot);
            }
        }
    }
    let mut reserved_owners = BTreeSet::new();
    for reservation in &snapshot.reservations {
        if execution_owners.get(&reservation.node) != Some(&reservation.owner)
            || !used.contains(&reservation.operation)
            || !reserved_owners.insert(reservation.owner.clone())
        {
            return Err(SchedulingError::InvalidSnapshot);
        }
        validate_permission(&reservation.permission, snapshot.maximum_microsteps)?;
        validate_reserved_contract(
            reservation,
            positions[&reservation.owner],
            &owner_contracts[&reservation.owner],
        )?;
        if reservation.input_batch.as_ref().is_some_and(|id| {
            !snapshot.input_batches.iter().any(|batch| {
                &batch.batch == id
                    && batch.owner == reservation.owner
                    && batch.activated_by.as_ref() == Some(&reservation.operation)
            })
        }) {
            return Err(SchedulingError::InvalidSnapshot);
        }
    }
    Ok(())
}

fn validate_reserved_contract(
    reservation: &SavedReservation,
    cursor: Position,
    contract: &(QuantumGrid, ExecutionPolicy),
) -> Result<(), SchedulingError> {
    let (grid, policy) = contract;
    match (&reservation.permission, policy) {
        (
            SavedPermission::ExactRun {
                start,
                limit,
                input_blocked_park,
            },
            ExecutionPolicy::Exact { ceiling, .. },
        ) if *start == cursor
            && grid.contains(limit.time_ps)
            && *input_blocked_park == matches!(ceiling, ExactCeiling::InputBlocked { .. }) =>
        {
            Ok(())
        }
        (
            SavedPermission::BoundarySettle { start, .. },
            ExecutionPolicy::Exact {
                boundary_settlement_ref: Some(_),
                ..
            },
        ) if *start == cursor => Ok(()),
        (
            SavedPermission::Quantum {
                start,
                end,
                input_batch,
                host_budget_ns,
                ..
            },
            ExecutionPolicy::Quantized {
                quantum_ps,
                host_budget_ns: selected_budget,
                ..
            },
        ) if *start == cursor
            && start.phase == Phase::BoundaryControl
            && start.microstep.get() == 0
            && end.phase == Phase::Publication
            && end.microstep.get() == 0
            && grid.contains(start.time_ps)
            && start.time_ps.checked_add(*quantum_ps)? == end.time_ps
            && host_budget_ns == selected_budget
            && reservation.input_batch.as_ref() == Some(input_batch) =>
        {
            Ok(())
        }
        _ => Err(SchedulingError::InvalidSnapshot),
    }
}

fn validate_delivery_lineage(delivery: &Delivery, cap: U64) -> Result<(), SchedulingError> {
    delivery.producer_endpoint.validate()?;
    delivery.consumer_endpoint.validate()?;
    if delivery.producer_endpoint.node_id != delivery.producer
        || delivery.consumer_endpoint.node_id != delivery.consumer
    {
        return Err(SchedulingError::InvalidSnapshot);
    }
    validate_position(delivery.publication, cap)?;
    validate_position(delivery.delivery, cap)?;
    if delivery.causal_parents.len() > MAX_ARRAY_ELEMENTS {
        return Err(SchedulingError::InvalidSnapshot);
    }
    if let Some(evaluation) = delivery.evaluation {
        validate_position(evaluation, cap)?;
        if crate::node_scheduling::event::reaction_publication(
            &delivery.causal_parents,
            evaluation,
            delivery.publication.time_ps,
            cap,
        )? != delivery.publication
        {
            return Err(SchedulingError::InvalidSnapshot);
        }
    } else {
        // Original quantized input parents retain causality at the fixed later
        // publication boundary without creating an evaluation coordinate. Same-
        // instant reactions still require an authentic evaluation and microstep.
        if delivery.publication.microstep.get() != 0
            || delivery
                .causal_parents
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            || delivery
                .causal_parents
                .iter()
                .any(|parent| parent.time_ps >= delivery.publication.time_ps)
        {
            return Err(SchedulingError::InvalidSnapshot);
        }
        for parent in &delivery.causal_parents {
            validate_position(*parent, cap)?;
        }
    }
    Ok(())
}

pub(crate) fn validate_structure(snapshot: &SchedulingSnapshot) -> Result<(), SchedulingError> {
    snapshot.world_binding_hash.validate()?;
    if snapshot.schema_version != 1
        || snapshot.ordering_profile != "superdense-v1"
        || snapshot.source_generation.get() == 0
    {
        return Err(SchedulingError::InvalidSnapshot);
    }
    bounded_sorted(&snapshot.source_owners, |owner| owner.owner.clone())?;
    bounded_sorted(&snapshot.positions, |position| position.owner.clone())?;
    bounded_sorted(&snapshot.producers, |producer| producer.node.clone())?;
    bounded_sorted(&snapshot.used_operations, Clone::clone)?;
    bounded_sorted(&snapshot.used_input_batches, Clone::clone)?;
    bounded_sorted(&snapshot.input_batches, |batch| batch.owner.clone())?;
    bounded_sorted(&snapshot.reservations, |reservation| {
        reservation.operation.clone()
    })?;
    bounded_sorted(&snapshot.pending_deliveries, Delivery::key)?;
    bounded_sorted(&snapshot.external_closed_prefixes, |saved| {
        saved.endpoint.clone()
    })?;
    for saved in &snapshot.external_closed_prefixes {
        validate_position(saved.closed_before, snapshot.maximum_microsteps)?;
    }
    bounded_sorted(&snapshot.native_sequences, |saved| saved.endpoint.clone())?;
    bounded_sorted(&snapshot.payload_objects, |saved| saved.reference.clone())?;
    validate_position(snapshot.source_boundary, snapshot.maximum_microsteps)?;
    validate_position(snapshot.capture_cut, snapshot.maximum_microsteps)?;
    for position in &snapshot.positions {
        validate_position(position.position, snapshot.maximum_microsteps)?;
    }
    for producer in &snapshot.producers {
        validate_position(producer.closed_prefix, snapshot.maximum_microsteps)?;
        if let SavedBound::At { position } = producer.bound {
            validate_position(position, snapshot.maximum_microsteps)?;
            if position.phase != Phase::Publication {
                return Err(SchedulingError::InvalidSnapshot);
            }
        }
    }
    for payload in &snapshot.payload_objects {
        payload.reference.validate()?;
        if crucible_node_contract::canonical::content_ref(
            &payload.bytes,
            &payload.reference.media_type,
        )? != payload.reference
        {
            return Err(SchedulingError::InvalidSnapshot);
        }
    }
    for batch in &snapshot.input_batches {
        validate_position(batch.cutoff, snapshot.maximum_microsteps)?;
        batch.inventory.validate()?;
        bounded_sorted(&batch.deliveries, Delivery::key)?;
        bounded_sorted(&batch.payloads, |payload| payload.reference.clone())?;
        if batch.consumed.len() > batch.deliveries.len()
            || batch
                .consumed
                .iter()
                .zip(&batch.deliveries)
                .any(|(identity, delivery)| {
                    *identity != super::super::inputs_impl::input_identity(delivery)
                })
        {
            return Err(SchedulingError::InvalidSnapshot);
        }
        let bytes = crucible_node_contract::canonical::canonical_json(
            &serde_json::to_value(&batch.deliveries)
                .map_err(crucible_node_contract::ContractError::from)?,
        )?;
        if crucible_node_contract::canonical::content_ref(
            &bytes,
            "application/vnd.crucible.input-inventory+json",
        )? != batch.inventory
        {
            return Err(SchedulingError::InvalidSnapshot);
        }
        for delivery in &batch.deliveries {
            if delivery.delivery >= batch.cutoff {
                return Err(SchedulingError::InvalidSnapshot);
            }
            validate_delivery_lineage(delivery, snapshot.maximum_microsteps)?;
            let payload = batch
                .payloads
                .iter()
                .find(|payload| payload.reference == delivery.payload)
                .ok_or(SchedulingError::InvalidSnapshot)?;
            if crucible_node_contract::canonical::content_ref(
                &payload.bytes,
                &payload.reference.media_type,
            )? != payload.reference
            {
                return Err(SchedulingError::InvalidSnapshot);
            }
        }
        if let Some(ack) = &batch.acknowledgement {
            ack.proof_ref.validate()?;
            if ack.node != batch.node
                || ack.stage_operation != batch.stage_operation
                || ack.batch != batch.batch
                || ack.owners != batch.owners
                || ack.cutoff != batch.cutoff
                || ack.inventory != batch.inventory
            {
                return Err(SchedulingError::InvalidSnapshot);
            }
        }
    }
    for reservation in &snapshot.reservations {
        validate_permission(&reservation.permission, snapshot.maximum_microsteps)?;
    }
    Ok(())
}

fn validate_position(position: Position, maximum_microsteps: U64) -> Result<(), SchedulingError> {
    if position.microstep >= maximum_microsteps
        && !(maximum_microsteps.get() == 0 && position.microstep.get() == 0)
    {
        return Err(SchedulingError::InvalidSnapshot);
    }
    Ok(())
}

fn validate_permission(
    permission: &SavedPermission,
    maximum_microsteps: U64,
) -> Result<(), SchedulingError> {
    let (start, limit) = match permission {
        SavedPermission::ExactRun { start, limit, .. } => {
            if limit.phase != Phase::BoundaryControl
                || limit.microstep.get() != 0
                || start.time_ps >= limit.time_ps
            {
                return Err(SchedulingError::InvalidSnapshot);
            }
            (*start, *limit)
        }
        SavedPermission::BoundarySettle { start, limit } => {
            if start.time_ps != limit.time_ps {
                return Err(SchedulingError::InvalidSnapshot);
            }
            (*start, *limit)
        }
        SavedPermission::Quantum {
            start,
            end,
            host_budget_ns,
            ..
        } => {
            if start.time_ps >= end.time_ps || host_budget_ns.get() == 0 {
                return Err(SchedulingError::InvalidSnapshot);
            }
            (*start, *end)
        }
    };
    validate_position(start, maximum_microsteps)?;
    validate_position(limit, maximum_microsteps)?;
    if start >= limit {
        return Err(SchedulingError::InvalidSnapshot);
    }
    Ok(())
}

fn bounded_sorted<T, K: Ord>(values: &[T], key: impl Fn(&T) -> K) -> Result<(), SchedulingError> {
    if values.len() > MAX_ARRAY_ELEMENTS
        || values.windows(2).any(|pair| key(&pair[0]) >= key(&pair[1]))
    {
        return Err(SchedulingError::InvalidSnapshot);
    }
    Ok(())
}

fn validate_external_delivery(
    graph: &AdmittedGraph,
    delivery: &Delivery,
    cap: U64,
) -> Result<(), SchedulingError> {
    let endpoint = delivery
        .external_root
        .as_ref()
        .ok_or(SchedulingError::InvalidSnapshot)?;
    if !graph
        .coordinator_policy()
        .external_inputs
        .contains(endpoint)
        || delivery.connection_id.is_some()
        || delivery.connection_policy_ref.is_some()
        || delivery.producer_endpoint != *endpoint
        || delivery.consumer_endpoint != *endpoint
        || delivery.producer != endpoint.node_id
        || delivery.consumer != endpoint.node_id
        || delivery.publication.phase != Phase::Publication
        || delivery.publication.microstep.get() != 0
        || delivery.evaluation.is_some()
        || !delivery.causal_parents.is_empty()
    {
        return Err(SchedulingError::InvalidSnapshot);
    }
    validate_delivery_lineage(delivery, cap)?;
    let descriptor = graph
        .descriptor(&endpoint.node_id)
        .and_then(|node| node.ports.iter().find(|port| port.id == endpoint.port_id))
        .and_then(|port| port.lanes.iter().find(|lane| lane.id == endpoint.lane_id))
        .ok_or(SchedulingError::InvalidSnapshot)?;
    if delivery.payload.length > descriptor.maximum_payload_bytes {
        return Err(SchedulingError::InvalidSnapshot);
    }
    let policy = graph
        .port_policy(&endpoint.node_id, &endpoint.port_id)
        .and_then(|port| {
            port.lanes
                .iter()
                .find(|lane| lane.lane_id == endpoint.lane_id)
        })
        .ok_or(SchedulingError::InvalidSnapshot)?;
    let grid = match policy.visibility {
        crate::node_admission::LaneVisibility::Exact => None,
        crate::node_admission::LaneVisibility::Quantized {
            quantum_ps,
            phase_ps,
            ..
        } => Some(QuantumGrid::new(quantum_ps, phase_ps)?),
    };
    if crate::node_scheduling::event::direct_delivery(delivery.publication, U64::new(0), grid)?
        != delivery.delivery
    {
        return Err(SchedulingError::InvalidSnapshot);
    }
    Ok(())
}
