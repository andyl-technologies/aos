//! Canonical evidence encoding for network state and control-plane outcomes.
//!
//! Every variable-width field is framed explicitly so replay and checkpoint
//! identity never depend on host layout or ambiguous concatenation.

use super::*;

pub(super) fn parse_control_object_id(
    bytes: &[u8],
    action: &ResolvedBindingAction,
) -> Result<FaultObjectId, SchedulerError> {
    let text = std::str::from_utf8(bytes).map_err(|_error| {
        network_effect_application_error(action, "replacement control object ID is not UTF-8")
    })?;
    FaultObjectId::parse(text.to_owned()).map_err(|_error| {
        network_effect_application_error(action, "replacement control object ID is invalid")
    })
}

pub(super) fn control_plane_outcome_evidence(
    outcome: &boundary::ControlPlaneOutcome,
) -> Result<ContentHash, SchedulerError> {
    let mut material = Vec::new();
    material.extend_from_slice(&outcome.action.id().bytes);
    material.push(match outcome.kind {
        boundary::ControlPlaneOutcomeKind::Dropped => 1,
        boundary::ControlPlaneOutcomeKind::TypedError => 2,
        boundary::ControlPlaneOutcomeKind::TimedOut => 3,
    });
    match &outcome.result {
        Some(result) => {
            material.push(1);
            append_evidence_bytes(&mut material, result.as_str().as_bytes())?;
        }
        None => material.push(0),
    }
    Ok(ContentHash::from_bytes(&material))
}

#[allow(
    clippy::too_many_arguments,
    reason = "evidence commits every independent availability-transition input"
)]
pub(super) fn availability_transition_evidence(
    action: &ResolvedBindingAction,
    old_state: NetworkAvailabilityState,
    state: NetworkAvailabilityState,
    queued_policy: NetworkInFlightPolicy,
    in_flight_policy: NetworkInFlightPolicy,
    source: &crucible::NodeId,
    destination: &crucible::NodeId,
    in_flight: &crucible::NetworkInFlightDropEvidence,
    queued: &[crucible::BackendNetworkOutput],
) -> Result<ContentHash, SchedulerError> {
    let mut material = Vec::new();
    material.extend_from_slice(&action.id().bytes);
    material.extend_from_slice(&action.transition_sequence.to_be_bytes());
    append_evidence_bytes(&mut material, action.phase.as_str().as_bytes())?;
    material.push(availability_state_tag(old_state));
    material.push(availability_state_tag(state));
    material.push(in_flight_policy_tag(queued_policy));
    material.push(in_flight_policy_tag(in_flight_policy));
    append_evidence_bytes(&mut material, source.name.as_bytes())?;
    append_evidence_bytes(&mut material, destination.name.as_bytes())?;
    material.extend_from_slice(&in_flight.evidence.bytes);
    let queued_count =
        u64::try_from(queued.len()).map_err(|_error| SchedulerError::BoundaryViolation {
            message: String::from("queued network transition evidence exceeds the canonical width"),
        })?;
    material.extend_from_slice(&queued_count.to_be_bytes());
    for output in queued {
        append_backend_output_evidence(&mut material, output)?;
    }
    Ok(ContentHash::from_bytes(&material))
}

pub(super) fn append_backend_output_evidence(
    material: &mut Vec<u8>,
    output: &crucible::BackendNetworkOutput,
) -> Result<(), SchedulerError> {
    append_evidence_bytes(material, output.source.name.as_bytes())?;
    append_evidence_bytes(material, output.destination.name.as_bytes())?;
    material.extend_from_slice(&output.emit_icount.retired.to_be_bytes());
    material.extend_from_slice(&output.sequence.to_be_bytes());
    match &output.route {
        Some(route) => {
            material.push(1);
            append_evidence_bytes(material, route.link.name.as_bytes())?;
            material.push(match route.direction {
                crucible::NetworkLinkDirection::EndpointAToEndpointB => 1,
                crucible::NetworkLinkDirection::EndpointBToEndpointA => 2,
            });
            append_evidence_bytes(material, route.destination.name.as_bytes())?;
        }
        None => material.push(0),
    }
    let preserved_count = u64::try_from(output.fault_continuation.preserved_availability().len())
        .map_err(|_error| SchedulerError::BoundaryViolation {
        message: String::from("preserved network profile count exceeds the canonical width"),
    })?;
    material.extend_from_slice(&preserved_count.to_be_bytes());
    for preserved in output.fault_continuation.preserved_availability() {
        append_evidence_bytes(material, preserved.binding.as_str().as_bytes())?;
        append_evidence_bytes(material, preserved.target.canonical_material().as_bytes())?;
        append_evidence_bytes(material, preserved.phase.as_str().as_bytes())?;
        material.extend_from_slice(&preserved.transition_sequence.to_be_bytes());
    }
    append_evidence_count(
        material,
        output.fault_continuation.protocol_expansion_path().len(),
    )?;
    for ordinal in output.fault_continuation.protocol_expansion_path() {
        material.extend_from_slice(&ordinal.to_be_bytes());
    }
    material.push(output.fault_continuation.generated_response_depth());
    match output.fault_continuation.generated_response_cause() {
        Some(cause) => {
            material.push(1);
            material.extend_from_slice(&cause.bytes);
        }
        None => material.push(0),
    }
    append_evidence_count(
        material,
        output.fault_continuation.forwarding_mutation_path().len(),
    )?;
    for cause in output.fault_continuation.forwarding_mutation_path() {
        material.extend_from_slice(&cause.bytes);
    }
    match output.fault_continuation.forced_route_destination() {
        Some(destination) => {
            material.push(1);
            append_evidence_bytes(material, destination.name.as_bytes())?;
        }
        None => material.push(0),
    }
    let cursor = output.fault_continuation.cursor();
    append_evidence_count(material, cursor.completed_phases().len())?;
    for completed in cursor.completed_phases() {
        append_evidence_bytes(material, completed.target.canonical_material().as_bytes())?;
        append_evidence_bytes(material, completed.phase.as_str().as_bytes())?;
    }
    material.extend_from_slice(&cursor.not_before_nanos().to_be_bytes());
    material.extend_from_slice(&cursor.release_nanos().to_be_bytes());
    match cursor.queue_opportunity() {
        Some(opportunity) => {
            material.push(1);
            material.extend_from_slice(&opportunity.bytes);
        }
        None => material.push(0),
    }
    match cursor.repeated_phase_effect() {
        Some(effect) => {
            material.push(1);
            append_evidence_bytes(material, effect.as_str().as_bytes())?;
        }
        None => material.push(0),
    }
    match cursor.queue_priority() {
        Some(priority) => {
            material.push(1);
            material.push(priority);
        }
        None => material.push(0),
    }
    match cursor.route_path_version() {
        Some(path) => {
            material.push(1);
            append_evidence_bytes(material, path.as_str().as_bytes())?;
        }
        None => material.push(0),
    }
    let effects = output.fault_continuation.resolved_frame_effects();
    material.extend_from_slice(&effects.latency_delta_nanos().to_be_bytes());
    material.extend_from_slice(&effects.additional_delay_nanos().to_be_bytes());
    material.push(u8::from(effects.is_dropped()));
    material.push(u8::from(effects.serialization_is_accounted()));
    append_evidence_count(material, effects.accounted_contact_services().len())?;
    for identity in effects.accounted_contact_services() {
        material.extend_from_slice(identity);
    }
    match effects.serialization_rate_cap_bps() {
        Some(rate) => {
            material.push(1);
            material.extend_from_slice(&rate.to_be_bytes());
        }
        None => material.push(0),
    }
    let duplicate_count =
        u64::try_from(effects.duplicate_gaps_nanos().len()).map_err(|_error| {
            SchedulerError::BoundaryViolation {
                message: String::from("network duplicate count exceeds the canonical width"),
            }
        })?;
    material.extend_from_slice(&duplicate_count.to_be_bytes());
    for gap in effects.duplicate_gaps_nanos() {
        material.extend_from_slice(&gap.to_be_bytes());
    }
    append_evidence_bytes(material, &output.payload)
}

pub(super) fn append_network_effect_state(
    material: &mut Vec<u8>,
    state: &NetworkEffectRuntimeState,
) -> Result<(), SchedulerError> {
    append_evidence_count(material, state.token_buckets.len())?;
    for (key, bucket) in &state.token_buckets {
        append_network_effect_state_key(material, key)?;
        material.extend_from_slice(&bucket.tokens_nano_bits.to_be_bytes());
        material.extend_from_slice(&bucket.last_refill_nanos.to_be_bytes());
        material.extend_from_slice(&bucket.transition_sequence.to_be_bytes());
    }
    append_evidence_count(material, state.queues.len())?;
    for (target, queue) in &state.queues {
        append_evidence_bytes(material, target.canonical_material().as_bytes())?;
        match &queue.configuration {
            Some(configuration) => {
                material.push(1);
                append_network_effect_state_key(material, &configuration.owner)?;
                material.push(network_queue_discipline_tag(configuration.discipline));
                match &configuration.discipline_parameters {
                    Some(reference) => {
                        material.push(1);
                        append_evidence_bytes(material, reference.as_str().as_bytes())?;
                    }
                    None => material.push(0),
                }
            }
            None => material.push(0),
        }
        material.extend_from_slice(&queue.service_cursor_nanos.to_be_bytes());
        append_evidence_count(material, queue.reservations.len())?;
        for reservation in &queue.reservations {
            material.extend_from_slice(&reservation.enqueue_nanos.to_be_bytes());
            material.extend_from_slice(&reservation.base_ready_nanos.to_be_bytes());
            material.extend_from_slice(&reservation.ready_nanos.to_be_bytes());
            material.extend_from_slice(&reservation.service_start_nanos.to_be_bytes());
            material.extend_from_slice(&reservation.finish_nanos.to_be_bytes());
            material.extend_from_slice(&reservation.bytes.to_be_bytes());
            material.extend_from_slice(&reservation.payload_bits.to_be_bytes());
            material.extend_from_slice(&reservation.remaining_nano_bits.to_be_bytes());
            match reservation.base_rate_bps {
                Some(rate) => {
                    material.push(1);
                    material.extend_from_slice(&rate.to_be_bytes());
                }
                None => material.push(0),
            }
            append_evidence_count(material, reservation.service_curves.len())?;
            for curve in &reservation.service_curves {
                material.extend_from_slice(&curve.activation_nanos.to_be_bytes());
                append_evidence_count(material, curve.segments.len())?;
                for segment in &curve.segments {
                    material.extend_from_slice(&segment.at_nanos.to_be_bytes());
                    material.extend_from_slice(&segment.rate_bps.get().to_be_bytes());
                }
            }
            match &reservation.class {
                Some(class) => {
                    material.push(1);
                    append_evidence_bytes(material, class.as_str().as_bytes())?;
                }
                None => material.push(0),
            }
            material.extend_from_slice(&reservation.opportunity.bytes);
        }
        append_evidence_count(material, queue.served_frames_by_class.len())?;
        for (class, count) in &queue.served_frames_by_class {
            append_evidence_bytes(material, class.as_str().as_bytes())?;
            material.extend_from_slice(&count.to_be_bytes());
        }
        append_evidence_count(material, queue.served_bytes_by_class.len())?;
        for (class, count) in &queue.served_bytes_by_class {
            append_evidence_bytes(material, class.as_str().as_bytes())?;
            material.extend_from_slice(&count.to_be_bytes());
        }
        material.extend_from_slice(&queue.red_average_bytes_q32.to_be_bytes());
    }
    append_evidence_count(material, state.burst_states.len())?;
    for (key, current) in &state.burst_states {
        append_network_effect_state_key(material, key)?;
        append_evidence_bytes(material, current.as_str().as_bytes())?;
    }
    append_evidence_count(material, state.state_machines.len())?;
    for (key, machine) in &state.state_machines {
        append_network_effect_state_key(material, key)?;
        append_network_state_machine(material, machine)?;
    }
    append_evidence_count(material, state.connection_tables.len())?;
    for (key, table) in &state.connection_tables {
        append_network_effect_state_key(material, key)?;
        append_evidence_count(material, table.len())?;
        for (flow, entry) in table {
            material.extend_from_slice(&flow.bytes);
            append_network_state_machine(material, &entry.machine)?;
            material.extend_from_slice(&entry.created_by.bytes);
            material.extend_from_slice(&entry.last_used_nanos.to_be_bytes());
        }
    }
    append_evidence_count(material, state.shared_media.len())?;
    for (key, medium) in &state.shared_media {
        append_network_effect_state_key(material, key)?;
        append_evidence_count(material, medium.resources.len())?;
        for resource in &medium.resources {
            append_evidence_bytes(material, resource.as_str().as_bytes())?;
        }
        append_evidence_bytes(material, medium.policy.as_str().as_bytes())?;
        material.extend_from_slice(&medium.transition_sequence.to_be_bytes());
        material.extend_from_slice(&medium.service_cursor_nanos.to_be_bytes());
        append_evidence_count(material, medium.reservations.len())?;
        for reservation in &medium.reservations {
            material.extend_from_slice(&reservation.opportunity.bytes);
            append_evidence_bytes(material, reservation.producer.as_str().as_bytes())?;
            append_evidence_bytes(material, &reservation.arbitration_key)?;
            material.extend_from_slice(&reservation.arrival_nanos.to_be_bytes());
            material.extend_from_slice(&reservation.start_nanos.to_be_bytes());
            material.extend_from_slice(&reservation.finish_nanos.to_be_bytes());
            material.extend_from_slice(&reservation.duration_nanos.to_be_bytes());
            material.extend_from_slice(&reservation.transmit_power_femtowatts.to_be_bytes());
            material.push(u8::from(reservation.terminal_collision_applied));
        }
    }
    append_evidence_count(material, state.backpressure.len())?;
    for (key, pause) in &state.backpressure {
        append_network_effect_state_key(material, key)?;
        append_evidence_bytes(material, pause.class.as_str().as_bytes())?;
        match pause.paused_until {
            Some(until) => {
                material.push(1);
                material.extend_from_slice(&until.to_be_bytes());
            }
            None => material.push(0),
        }
        material.extend_from_slice(&pause.transition_sequence.to_be_bytes());
    }
    append_evidence_count(material, state.custody_queues.len())?;
    for (key, queue) in &state.custody_queues {
        append_network_effect_state_key(material, key)?;
        match &queue.configuration {
            Some(configuration) => {
                material.push(1);
                append_network_effect_state_key(material, &configuration.owner)?;
                material.extend_from_slice(&configuration.capacity_bytes.to_be_bytes());
                material.extend_from_slice(&configuration.capacity_bundles.to_be_bytes());
                material.extend_from_slice(&configuration.expiry_nanos.to_be_bytes());
                append_evidence_bytes(material, configuration.custody_policy.as_str().as_bytes())?;
                append_evidence_bytes(
                    material,
                    configuration.route_contact_plan.as_str().as_bytes(),
                )?;
                material.push(configuration.priority.rank());
                material.extend_from_slice(&configuration.max_visited_hops.to_be_bytes());
            }
            None => material.push(0),
        }
        append_evidence_count(material, queue.reservations.len())?;
        for reservation in &queue.reservations {
            append_network_bundle_identity(material, &reservation.bundle)?;
            material.extend_from_slice(&reservation.opportunity.bytes);
            material.extend_from_slice(&reservation.enqueue_nanos.to_be_bytes());
            material.extend_from_slice(&reservation.expiry_nanos.to_be_bytes());
            material.extend_from_slice(&reservation.release_nanos.to_be_bytes());
            material.extend_from_slice(&reservation.bytes.to_be_bytes());
            append_evidence_count(material, reservation.contact_path.len())?;
            for contact in &reservation.contact_path {
                append_evidence_bytes(material, contact.as_str().as_bytes())?;
            }
            material.push(u8::from(reservation.contact_path_committed));
        }
        append_evidence_count(material, queue.overflow_timeouts.len())?;
        for timeout in &queue.overflow_timeouts {
            append_network_bundle_identity(material, &timeout.bundle)?;
            material.extend_from_slice(&timeout.opportunity.bytes);
            material.extend_from_slice(&timeout.enqueue_nanos.to_be_bytes());
            material.extend_from_slice(&timeout.expiry_nanos.to_be_bytes());
            material.extend_from_slice(&timeout.deadline_nanos.to_be_bytes());
        }
        material.extend_from_slice(&queue.admitted_bundles.to_be_bytes());
        material.extend_from_slice(&queue.released_bundles.to_be_bytes());
        material.extend_from_slice(&queue.dropped_bundles.to_be_bytes());
        material.extend_from_slice(&queue.expired_bundles.to_be_bytes());
        material.extend_from_slice(&queue.missed_contact_bundles.to_be_bytes());
        material.extend_from_slice(&queue.stale_plan_bundles.to_be_bytes());
    }
    append_evidence_count(material, state.contact_services.len())?;
    for (key, service) in &state.contact_services {
        append_evidence_bytes(material, key.plan.as_str().as_bytes())?;
        append_evidence_bytes(material, key.contact.as_str().as_bytes())?;
        append_evidence_bytes(material, key.service_resource.as_str().as_bytes())?;
        append_evidence_bytes(material, key.source.as_str().as_bytes())?;
        append_evidence_bytes(material, key.destination.as_str().as_bytes())?;
        material.extend_from_slice(&key.start_nanos.to_be_bytes());
        material.extend_from_slice(&key.end_nanos.to_be_bytes());
        material.extend_from_slice(&service.settled_cursor_nanos.to_be_bytes());
        material.extend_from_slice(&service.service_cursor_nanos.to_be_bytes());
        material.extend_from_slice(&service.served_bundles.to_be_bytes());
        material.extend_from_slice(&service.served_bytes.to_be_bytes());
        append_evidence_count(material, service.reservations.len())?;
        for reservation in &service.reservations {
            match &reservation.custody_owner {
                Some(owner) => {
                    material.push(1);
                    append_network_effect_state_key(material, owner)?;
                }
                None => material.push(0),
            }
            material.extend_from_slice(&reservation.opportunity.bytes);
            material.extend_from_slice(&reservation.start_nanos.to_be_bytes());
            material.extend_from_slice(&reservation.finish_nanos.to_be_bytes());
            material.extend_from_slice(&reservation.arrival_nanos.to_be_bytes());
            material.extend_from_slice(&reservation.bytes.to_be_bytes());
        }
    }
    state.boundary.append_evidence(material)
}

pub(super) fn append_network_bundle_identity(
    material: &mut Vec<u8>,
    bundle: &NetworkBundleIdentity,
) -> Result<(), SchedulerError> {
    append_evidence_bytes(material, bundle.producer.as_str().as_bytes())?;
    append_evidence_bytes(material, bundle.destination.as_str().as_bytes())?;
    material.extend_from_slice(&bundle.producer_sequence.to_be_bytes());
    append_evidence_count(material, bundle.protocol_expansion_path.len())?;
    for ordinal in &bundle.protocol_expansion_path {
        material.extend_from_slice(&ordinal.to_be_bytes());
    }
    material.push(bundle.generated_response_depth);
    match bundle.generated_response_cause {
        Some(cause) => {
            material.push(1);
            material.extend_from_slice(&cause.bytes);
        }
        None => material.push(0),
    }
    append_evidence_count(material, bundle.forwarding_mutation_path.len())?;
    for opportunity in &bundle.forwarding_mutation_path {
        material.extend_from_slice(&opportunity.bytes);
    }
    material.extend_from_slice(&bundle.length_bytes.to_be_bytes());
    material.extend_from_slice(&bundle.payload_digest.bytes);
    material.push(bundle.priority.rank());
    Ok(())
}

pub(super) fn append_network_state_machine(
    material: &mut Vec<u8>,
    machine: &NetworkStateMachineRuntime,
) -> Result<(), SchedulerError> {
    append_evidence_bytes(material, machine.current.as_str().as_bytes())?;
    append_evidence_count(material, machine.pending.len())?;
    for pending in &machine.pending {
        append_evidence_bytes(material, pending.state.as_str().as_bytes())?;
        material.extend_from_slice(&pending.commit_nanos.to_be_bytes());
    }
    material.extend_from_slice(&machine.transition_sequence.to_be_bytes());
    Ok(())
}

pub(super) const fn network_queue_discipline_tag(
    discipline: crucible::model::NetworkQueueDiscipline,
) -> u8 {
    match discipline {
        crucible::model::NetworkQueueDiscipline::Fifo => 1,
        crucible::model::NetworkQueueDiscipline::StrictPriority => 2,
        crucible::model::NetworkQueueDiscipline::WeightedRoundRobin => 3,
        crucible::model::NetworkQueueDiscipline::DeficitRoundRobin => 4,
        crucible::model::NetworkQueueDiscipline::Red => 5,
    }
}

pub(super) fn append_network_effect_state_key(
    material: &mut Vec<u8>,
    key: &NetworkEffectStateKey,
) -> Result<(), SchedulerError> {
    append_evidence_bytes(material, key.binding.as_str().as_bytes())?;
    append_evidence_bytes(material, key.target.canonical_material().as_bytes())?;
    append_evidence_bytes(material, key.effect.as_str().as_bytes())
}

pub(super) fn append_evidence_count(
    material: &mut Vec<u8>,
    count: usize,
) -> Result<(), SchedulerError> {
    let count = u64::try_from(count).map_err(|_error| SchedulerError::BoundaryViolation {
        message: String::from("network effect-state collection exceeds the canonical width"),
    })?;
    material.extend_from_slice(&count.to_be_bytes());
    Ok(())
}

pub(super) fn append_evidence_bytes(
    output: &mut Vec<u8>,
    value: &[u8],
) -> Result<(), SchedulerError> {
    let length =
        u64::try_from(value.len()).map_err(|_error| SchedulerError::BoundaryViolation {
            message: String::from("network transition evidence value exceeds the canonical width"),
        })?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

pub(super) const fn availability_state_tag(state: NetworkAvailabilityState) -> u8 {
    match state {
        NetworkAvailabilityState::Up => 1,
        NetworkAvailabilityState::Down => 2,
        NetworkAvailabilityState::ReceiveOnly => 3,
        NetworkAvailabilityState::TransmitOnly => 4,
    }
}

pub(super) const fn in_flight_policy_tag(policy: NetworkInFlightPolicy) -> u8 {
    match policy {
        NetworkInFlightPolicy::Preserve => 1,
        NetworkInFlightPolicy::Reevaluate => 2,
        NetworkInFlightPolicy::Drop => 3,
        NetworkInFlightPolicy::TypedError => 4,
    }
}
