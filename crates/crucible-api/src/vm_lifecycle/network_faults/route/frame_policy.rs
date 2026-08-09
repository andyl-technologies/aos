//! Forwarding, queueing, shared-medium, and typed-response frame policy.
//!
//! The parent route executor owns transaction boundaries; this module computes
//! the deterministic frame disposition and reservations made within one such
//! transaction.

use super::*;

#[derive(Clone, Debug, Default)]
pub(super) struct NetworkFrameApplication {
    pub(super) defer_until: Option<u64>,
    pub(super) repeat_effect_on_resume: Option<crucible::model::EffectKind>,
    pub(super) queue_priority: Option<u8>,
    pub(super) next_wakeup_nanos: Option<u64>,
    pub(super) expanded_payloads: Vec<Vec<u8>>,
    pub(super) typed_response: Option<FaultObjectId>,
    pub(super) forwarding_recipients: Option<Vec<FaultObjectId>>,
}

pub(in super::super) fn apply_network_forwarding_mutation(
    payload: &[u8],
    topology: &crucible::model::WorldFaultTopology,
    action: &ResolvedBindingAction,
    opportunity: &FaultOpportunity,
    selector: &FaultObjectId,
    mutation: &crucible::model::NetworkForwardingMutationKind,
    recipients: &mut Option<Vec<FaultObjectId>>,
) -> Result<(), SchedulerError> {
    if !network_packet_selector_matches(payload, topology, selector, action)? {
        return Ok(());
    }
    use crucible::model::{
        NetworkForwardingMutationKind as Mutation, NetworkStaleEntryDisposition,
    };
    let replacement = match mutation {
        Mutation::WrongPort { recipient } => Some(vec![recipient.clone()]),
        Mutation::Flood { recipients } => Some(recipients.as_slice().to_vec()),
        Mutation::Blackhole => Some(Vec::new()),
        Mutation::Loop {
            next_hop,
            hop_limit,
        } => {
            let OpportunityPayload::NetworkFrame {
                forwarding_mutation_path,
                ..
            } = opportunity.payload()
            else {
                return Err(network_effect_application_error(
                    action,
                    "forwarding mutation received a non-frame opportunity",
                ));
            };
            if u64::try_from(forwarding_mutation_path.len())
                .map_or(true, |depth| depth >= hop_limit.get())
            {
                Some(Vec::new())
            } else {
                Some(vec![next_hop.clone()])
            }
        }
        Mutation::StaleAge {
            age_nanos,
            expiration_nanos,
            expired,
        } if *age_nanos >= expiration_nanos.get() => match expired {
            NetworkStaleEntryDisposition::Preserve => None,
            NetworkStaleEntryDisposition::Blackhole => Some(Vec::new()),
            NetworkStaleEntryDisposition::Flood { recipients } => {
                Some(recipients.as_slice().to_vec())
            }
        },
        Mutation::StaleAge { .. } => None,
    };
    if let Some(replacement) = replacement {
        *recipients = Some(replacement);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(in super::super) fn apply_network_firewall(
    payload: &[u8],
    effects: &mut crucible::ResolvedNetworkFrameEffects,
    state: &mut NetworkEffectRuntimeState,
    topology: &crucible::model::WorldFaultTopology,
    action: &ResolvedBindingAction,
    opportunity: &FaultOpportunity,
    disposition: crucible::model::NetworkFirewallAction,
    typed_reject: Option<&FaultObjectId>,
    rule: &FaultObjectId,
    state_machine: &FaultObjectId,
    transition_event: &FaultObjectId,
    typed_response: &mut Option<FaultObjectId>,
) -> Result<Option<u64>, SchedulerError> {
    if !network_packet_selector_matches(payload, topology, rule, action)? {
        return Ok(None);
    }
    let key = NetworkEffectStateKey::from_action(action);
    let initial = network_state_machine_initial(topology, state_machine, action)?;
    let machine = state
        .state_machines
        .entry(key)
        .or_insert_with(|| NetworkStateMachineRuntime {
            current: initial,
            pending: Vec::new(),
            transition_sequence: action.transition_sequence,
        });
    let release = advance_network_state_machine(
        machine,
        topology,
        state_machine,
        transition_event,
        action,
        opportunity.coordinate().virtual_nanos,
    )?;
    match disposition {
        crucible::model::NetworkFirewallAction::Accept => {}
        crucible::model::NetworkFirewallAction::Drop => effects.mark_drop(),
        crucible::model::NetworkFirewallAction::Reject => {
            let response = typed_reject.ok_or_else(|| {
                network_effect_application_error(action, "firewall reject omitted its response")
            })?;
            request_typed_response(typed_response, response, action)?;
            effects.mark_drop();
        }
    }
    Ok(release)
}

#[allow(clippy::too_many_arguments)]
pub(in super::super) fn apply_network_connection_state(
    payload: &[u8],
    effects: &mut crucible::ResolvedNetworkFrameEffects,
    state: &mut NetworkEffectRuntimeState,
    topology: &crucible::model::WorldFaultTopology,
    action: &ResolvedBindingAction,
    opportunity: &FaultOpportunity,
    scenario_seed: ContentHash,
    table_bound: u32,
    flow_key: &FaultObjectId,
    state_machine: &FaultObjectId,
    transition_event: &FaultObjectId,
    overflow: &crucible::model::NetworkConnectionOverflow,
    typed_response: &mut Option<FaultObjectId>,
) -> Result<Option<u64>, SchedulerError> {
    let flow = network_packet_key(payload, topology, flow_key, action)?;
    let owner = NetworkEffectStateKey::from_action(action);
    let initial = network_state_machine_initial(topology, state_machine, action)?;
    let table = state.connection_tables.entry(owner).or_default();
    if !table.contains_key(&flow)
        && u32::try_from(table.len()).map_or(true, |length| length >= table_bound)
    {
        use crucible::model::NetworkConnectionOverflow as Overflow;
        match overflow {
            Overflow::DropNewest => {
                effects.mark_drop();
                return Ok(None);
            }
            Overflow::TypedError { response } => {
                request_typed_response(typed_response, response, action)?;
                effects.mark_drop();
                return Ok(None);
            }
            Overflow::EvictOldest => {
                let victim = table
                    .iter()
                    .min_by_key(|(identity, entry)| {
                        (entry.last_used_nanos, entry.created_by, **identity)
                    })
                    .map(|(identity, _entry)| *identity)
                    .ok_or_else(|| {
                        network_effect_application_error(
                            action,
                            "connection table reached its bound without an eviction candidate",
                        )
                    })?;
                table.remove(&victim);
            }
            Overflow::KeyedEviction => {
                let count = u64::try_from(table.len()).map_err(|_error| {
                    network_effect_application_error(
                        action,
                        "connection table candidate count exceeds u64",
                    )
                })?;
                let index = usize::try_from(
                    network_effect_draw(
                        scenario_seed,
                        opportunity,
                        action,
                        "connection-eviction",
                        0,
                    ) % count,
                )
                .map_err(|_error| {
                    network_effect_application_error(
                        action,
                        "connection eviction index exceeds host width",
                    )
                })?;
                let victim = table.keys().nth(index).copied().ok_or_else(|| {
                    network_effect_application_error(
                        action,
                        "connection eviction candidate disappeared",
                    )
                })?;
                table.remove(&victim);
            }
        }
    }
    let entry = table.entry(flow).or_insert_with(|| NetworkConnectionEntry {
        machine: NetworkStateMachineRuntime {
            current: initial,
            pending: Vec::new(),
            transition_sequence: action.transition_sequence,
        },
        created_by: opportunity.id(),
        last_used_nanos: opportunity.coordinate().virtual_nanos,
    });
    entry.last_used_nanos = opportunity.coordinate().virtual_nanos;
    advance_network_state_machine(
        &mut entry.machine,
        topology,
        state_machine,
        transition_event,
        action,
        opportunity.coordinate().virtual_nanos,
    )
}

pub(in super::super) fn network_packet_key(
    payload: &[u8],
    topology: &crucible::model::WorldFaultTopology,
    key: &FaultObjectId,
    action: &ResolvedBindingAction,
) -> Result<ContentHash, SchedulerError> {
    Ok(ContentHash::from_bytes(&network_packet_key_bytes(
        payload, topology, key, action,
    )?))
}

pub(in super::super) fn network_packet_key_bytes(
    payload: &[u8],
    topology: &crucible::model::WorldFaultTopology,
    key: &FaultObjectId,
    action: &ResolvedBindingAction,
) -> Result<Vec<u8>, SchedulerError> {
    let declaration = topology.network_policy_artifact(key).ok_or_else(|| {
        network_effect_application_error(action, "network packet key disappeared")
    })?;
    let crucible::model::NetworkPolicyArtifactKind::PacketKey { ranges } = &declaration.artifact
    else {
        return Err(network_effect_application_error(
            action,
            "network packet key changed type after admission",
        ));
    };
    let mut material = Vec::new();
    for range in ranges {
        let start = usize::try_from(range.start()).map_err(|_error| {
            network_effect_application_error(action, "packet key offset exceeds host width")
        })?;
        let end = usize::try_from(range.end()).map_err(|_error| {
            network_effect_application_error(action, "packet key end exceeds host width")
        })?;
        let bytes = payload.get(start..end).ok_or_else(|| {
            network_effect_application_error(action, "packet key range is outside the frame")
        })?;
        material.extend_from_slice(&range.length().to_be_bytes());
        material.extend_from_slice(bytes);
    }
    Ok(material)
}

#[allow(clippy::too_many_arguments)]
pub(in super::super) fn apply_network_shared_medium(
    payload: &mut [u8],
    effects: &mut crucible::ResolvedNetworkFrameEffects,
    state: &mut NetworkEffectRuntimeState,
    pending_outputs: &mut [crucible::BackendNetworkOutput],
    topology: &crucible::model::WorldFaultTopology,
    action: &ResolvedBindingAction,
    opportunity: &FaultOpportunity,
    scenario_seed: ContentHash,
    resources: &crucible::model::ObjectIdSet,
    policy_id: &FaultObjectId,
    transmit_power_femtowatts: u64,
    service_rate_bps: Option<u64>,
) -> Result<Option<u64>, SchedulerError> {
    let owner = NetworkEffectStateKey::from_action(action);
    if action.kind == BindingActionKind::RemovePersistent {
        state.shared_media.remove(&owner);
        return Ok(None);
    }
    let declaration = topology.network_policy_artifact(policy_id).ok_or_else(|| {
        network_effect_application_error(action, "shared-medium policy disappeared")
    })?;
    let crucible::model::NetworkPolicyArtifactKind::MediumAccess(policy) = &declaration.artifact
    else {
        return Err(network_effect_application_error(
            action,
            "shared-medium policy changed type after admission",
        ));
    };
    let policy = policy.clone();
    let OpportunityPayload::NetworkFrame { producer, .. } = opportunity.payload() else {
        return Err(network_effect_application_error(
            action,
            "shared-medium effect received a non-frame opportunity",
        ));
    };
    if resources.as_slice().binary_search(producer).is_err() {
        return Err(network_effect_application_error(
            action,
            "frame producer is absent from the shared-medium resource set",
        ));
    }
    let now = opportunity.coordinate().virtual_nanos;
    state.shared_media.retain(|_key, medium| {
        medium
            .reservations
            .retain(|reservation| reservation.finish_nanos > now);
        !medium.reservations.is_empty()
    });
    let active_reservations = state
        .shared_media
        .values()
        .try_fold(0_usize, |total, medium| {
            total.checked_add(medium.reservations.len())
        })
        .ok_or_else(|| {
            network_effect_application_error(action, "shared-medium reservation count overflowed")
        })?;
    if active_reservations == HARD_PENDING_NETWORK_FRAMES {
        return Err(network_effect_application_error(
            action,
            "shared-medium reservations reached the global hard bound",
        ));
    }
    let rate_bps = service_rate_bps.filter(|rate| *rate > 0).ok_or_else(|| {
        network_effect_application_error(
            action,
            "shared-medium service has neither a link rate nor a resolved rate cap",
        )
    })?;
    let payload_bits = u64::try_from(payload.len())
        .ok()
        .and_then(|bytes| bytes.checked_mul(8))
        .ok_or_else(|| network_effect_application_error(action, "medium frame size overflowed"))?;
    let duration_nanos = ceil_ratio_u128(
        u128::from(payload_bits)
            .checked_mul(1_000_000_000)
            .and_then(|value| value.checked_mul(u128::from(policy.duty_cycle_denominator.get())))
            .ok_or_else(|| {
                network_effect_application_error(action, "medium airtime demand overflowed")
            })?,
        u128::from(rate_bps)
            .checked_mul(u128::from(policy.duty_cycle_numerator.get()))
            .ok_or_else(|| {
                network_effect_application_error(action, "medium airtime rate overflowed")
            })?,
    )
    .and_then(|duration| u64::try_from(duration.max(1)).ok())
    .ok_or_else(|| network_effect_application_error(action, "medium airtime exceeds u64"))?;
    let arbitration_key = match policy.arbitration_key.as_ref() {
        Some(key) => network_packet_key_bytes(payload, topology, key, action)?,
        None => Vec::new(),
    };
    let undetected_transform = match policy
        .contention
        .as_ref()
        .and_then(|contention| contention.undetected_transform.as_ref())
    {
        Some(transform) => Some(network_byte_template(topology, transform, action)?.to_vec()),
        None => None,
    };
    let configured_resources = resources.as_slice().to_vec();
    let reset = state
        .shared_media
        .get(&owner)
        .is_none_or(|medium| medium.transition_sequence != action.transition_sequence);
    if reset {
        state.shared_media.insert(
            owner.clone(),
            NetworkMediumState {
                resources: configured_resources.clone(),
                policy: policy_id.clone(),
                transition_sequence: action.transition_sequence,
                service_cursor_nanos: now,
                reservations: Vec::new(),
            },
        );
    }
    let medium = state.shared_media.get_mut(&owner).ok_or_else(|| {
        network_effect_application_error(action, "shared-medium state insertion failed")
    })?;
    if medium.resources != configured_resources || medium.policy != *policy_id {
        return Err(network_effect_application_error(
            action,
            "shared-medium configuration changed without a new transition sequence",
        ));
    }
    let mut reservation = NetworkMediumReservation {
        opportunity: opportunity.id(),
        producer: producer.clone(),
        arbitration_key,
        arrival_nanos: now,
        start_nanos: now,
        finish_nanos: now,
        duration_nanos,
        transmit_power_femtowatts,
        terminal_collision_applied: false,
    };
    use crucible::model::{NetworkPolicyArbitration, NetworkPolicyCollision};
    let release = match policy.arbitration {
        NetworkPolicyArbitration::Fifo
        | NetworkPolicyArbitration::StrictPriority
        | NetworkPolicyArbitration::CanDominantBit => {
            medium.reservations.push(reservation);
            let current = medium.reservations.len() - 1;
            let mut candidates = medium
                .reservations
                .iter()
                .enumerate()
                .filter_map(|(index, candidate)| (candidate.start_nanos >= now).then_some(index))
                .collect::<Vec<_>>();
            if matches!(
                policy.arbitration,
                NetworkPolicyArbitration::StrictPriority | NetworkPolicyArbitration::CanDominantBit
            ) {
                candidates.sort_by(|left, right| {
                    medium.reservations[*left]
                        .arbitration_key
                        .cmp(&medium.reservations[*right].arbitration_key)
                        .then_with(|| {
                            medium.reservations[*left]
                                .opportunity
                                .cmp(&medium.reservations[*right].opportunity)
                        })
                });
            }
            let mut cursor = medium
                .reservations
                .iter()
                .filter(|candidate| candidate.start_nanos < now)
                .map(|candidate| candidate.finish_nanos)
                .max()
                .unwrap_or(now)
                .max(now);
            for index in candidates {
                let candidate = &mut medium.reservations[index];
                candidate.start_nanos = cursor;
                candidate.finish_nanos =
                    cursor
                        .checked_add(candidate.duration_nanos)
                        .ok_or_else(|| {
                            network_effect_application_error(action, "medium service overflowed")
                        })?;
                cursor = candidate.finish_nanos;
                if index != current {
                    reschedule_medium_output(
                        pending_outputs,
                        candidate.opportunity,
                        candidate.finish_nanos,
                        action,
                    )?;
                }
            }
            medium.service_cursor_nanos = cursor;
            medium.reservations[current].finish_nanos
        }
        NetworkPolicyArbitration::FixedSlots => {
            let slot_nanos = policy.fixed_slot_nanos.ok_or_else(|| {
                network_effect_application_error(action, "fixed-slot policy omitted slot width")
            })?;
            if duration_nanos > slot_nanos.get() {
                return Err(network_effect_application_error(
                    action,
                    "frame airtime exceeds its fixed medium slot",
                ));
            }
            let resource_index =
                resources
                    .as_slice()
                    .binary_search(producer)
                    .map_err(|_error| {
                        network_effect_application_error(action, "fixed-slot producer disappeared")
                    })?;
            let resource_count = u64::try_from(resources.as_slice().len()).map_err(|_error| {
                network_effect_application_error(action, "medium resource count exceeds u64")
            })?;
            let index = u64::try_from(resource_index).map_err(|_error| {
                network_effect_application_error(action, "medium resource index exceeds u64")
            })?;
            let cycle = slot_nanos
                .get()
                .checked_mul(resource_count)
                .ok_or_else(|| {
                    network_effect_application_error(action, "fixed-slot cycle overflowed")
                })?;
            let phase = slot_nanos.get().checked_mul(index).ok_or_else(|| {
                network_effect_application_error(action, "fixed-slot phase overflowed")
            })?;
            let mut start = (now / cycle)
                .checked_mul(cycle)
                .and_then(|cycle_start| cycle_start.checked_add(phase))
                .ok_or_else(|| {
                    network_effect_application_error(action, "fixed-slot coordinate overflowed")
                })?;
            if start < now {
                start = start.checked_add(cycle).ok_or_else(|| {
                    network_effect_application_error(action, "fixed-slot advance overflowed")
                })?;
            }
            while medium.reservations.iter().any(|existing| {
                existing.producer == *producer
                    && intervals_overlap(
                        start,
                        start.saturating_add(duration_nanos),
                        existing.start_nanos,
                        existing.finish_nanos,
                    )
            }) {
                start = start.checked_add(cycle).ok_or_else(|| {
                    network_effect_application_error(action, "fixed-slot retry overflowed")
                })?;
            }
            reservation.start_nanos = start;
            reservation.finish_nanos = start.checked_add(duration_nanos).ok_or_else(|| {
                network_effect_application_error(action, "fixed-slot finish overflowed")
            })?;
            let finish = reservation.finish_nanos;
            medium.service_cursor_nanos = medium.service_cursor_nanos.max(finish);
            medium.reservations.push(reservation);
            finish
        }
        NetworkPolicyArbitration::Contention => {
            let contention = policy.contention.as_ref().ok_or_else(|| {
                network_effect_application_error(action, "contention policy is absent")
            })?;
            let mut attempt = 0_u16;
            let (start, overlaps) = loop {
                let exponent =
                    u32::from(attempt.min(u16::from(contention.maximum_backoff_exponent)));
                let maximum_slot = (1_u64 << exponent).saturating_sub(1);
                let slot = uniform_inclusive(
                    network_effect_draw(
                        scenario_seed,
                        opportunity,
                        action,
                        "medium-backoff",
                        u64::from(attempt),
                    ),
                    maximum_slot,
                );
                let start = slot
                    .checked_mul(contention.backoff_slot_nanos.get())
                    .and_then(|delay| now.checked_add(delay))
                    .ok_or_else(|| {
                        network_effect_application_error(action, "medium backoff overflowed")
                    })?;
                let finish = start.checked_add(duration_nanos).ok_or_else(|| {
                    network_effect_application_error(action, "medium contention overflowed")
                })?;
                let overlaps = medium
                    .reservations
                    .iter()
                    .enumerate()
                    .filter_map(|(index, existing)| {
                        intervals_overlap(
                            start,
                            finish,
                            existing.start_nanos,
                            existing.finish_nanos,
                        )
                        .then_some(index)
                    })
                    .collect::<Vec<_>>();
                if overlaps.is_empty() || attempt == contention.maximum_retries {
                    break (start, overlaps);
                }
                attempt = attempt.checked_add(1).ok_or_else(|| {
                    network_effect_application_error(action, "medium retry count overflowed")
                })?;
            };
            reservation.start_nanos = start;
            reservation.finish_nanos = start.checked_add(duration_nanos).ok_or_else(|| {
                network_effect_application_error(action, "medium contention finish overflowed")
            })?;
            if !overlaps.is_empty() {
                reservation.terminal_collision_applied = true;
                match contention.collision {
                    NetworkPolicyCollision::DropAll => {
                        effects.mark_drop();
                        for index in overlaps {
                            drop_medium_output(
                                pending_outputs,
                                &mut medium.reservations[index],
                                action,
                            )?;
                        }
                    }
                    NetworkPolicyCollision::Capture => {
                        apply_medium_capture(
                            effects,
                            pending_outputs,
                            &mut medium.reservations,
                            &overlaps,
                            &reservation,
                            contention
                                .capture_threshold_millionths
                                .ok_or_else(|| {
                                    network_effect_application_error(
                                        action,
                                        "capture collision omitted its threshold",
                                    )
                                })?
                                .get(),
                            action,
                        )?;
                    }
                    NetworkPolicyCollision::UndetectedTransform => {
                        let transform = undetected_transform.as_deref().ok_or_else(|| {
                            network_effect_application_error(
                                action,
                                "undetected collision omitted its transform",
                            )
                        })?;
                        xor_repeated(payload, transform);
                        for index in overlaps {
                            transform_medium_output(
                                pending_outputs,
                                &mut medium.reservations[index],
                                transform,
                                action,
                            )?;
                        }
                    }
                }
            }
            let finish = reservation.finish_nanos;
            medium.service_cursor_nanos = medium.service_cursor_nanos.max(finish);
            medium.reservations.push(reservation);
            finish
        }
    };
    effects.mark_serialization_accounted();
    Ok(Some(release))
}

pub(in super::super) fn intervals_overlap(
    left_start: u64,
    left_end: u64,
    right_start: u64,
    right_end: u64,
) -> bool {
    left_start < right_end && right_start < left_end
}

pub(in super::super) fn reschedule_medium_output(
    pending_outputs: &mut [crucible::BackendNetworkOutput],
    opportunity: ContentHash,
    finish_nanos: u64,
    action: &ResolvedBindingAction,
) -> Result<(), SchedulerError> {
    let output = pending_medium_output(pending_outputs, opportunity, action)?;
    let release = output
        .fault_continuation
        .cursor()
        .not_before_nanos()
        .max(finish_nanos);
    output
        .fault_continuation
        .cursor_mut()
        .reschedule_queue_until(opportunity, release)
        .map_err(|error| {
            network_effect_application_error(
                action,
                &format!("reschedule shared-medium contender: {error}"),
            )
        })
}

pub(in super::super) fn drop_medium_output(
    pending_outputs: &mut [crucible::BackendNetworkOutput],
    reservation: &mut NetworkMediumReservation,
    action: &ResolvedBindingAction,
) -> Result<(), SchedulerError> {
    let output = pending_medium_output(pending_outputs, reservation.opportunity, action)?;
    let mut effects = output.fault_continuation.resolved_frame_effects().clone();
    effects.mark_drop();
    output
        .fault_continuation
        .set_resolved_frame_effects(effects);
    reservation.terminal_collision_applied = true;
    Ok(())
}

pub(in super::super) fn transform_medium_output(
    pending_outputs: &mut [crucible::BackendNetworkOutput],
    reservation: &mut NetworkMediumReservation,
    transform: &[u8],
    action: &ResolvedBindingAction,
) -> Result<(), SchedulerError> {
    if reservation.terminal_collision_applied {
        return Ok(());
    }
    let output = pending_medium_output(pending_outputs, reservation.opportunity, action)?;
    xor_repeated(&mut output.payload, transform);
    reservation.terminal_collision_applied = true;
    Ok(())
}

pub(in super::super) fn pending_medium_output<'a>(
    pending_outputs: &'a mut [crucible::BackendNetworkOutput],
    opportunity: ContentHash,
    action: &ResolvedBindingAction,
) -> Result<&'a mut crucible::BackendNetworkOutput, SchedulerError> {
    pending_outputs
        .iter_mut()
        .find(|output| output.fault_continuation.cursor().queue_opportunity() == Some(opportunity))
        .ok_or_else(|| {
            network_effect_application_error(
                action,
                "shared-medium reservation has no matching pending frame",
            )
        })
}

pub(in super::super) fn xor_repeated(payload: &mut [u8], transform: &[u8]) {
    for (index, byte) in payload.iter_mut().enumerate() {
        *byte ^= transform[index % transform.len()];
    }
}

#[allow(clippy::too_many_arguments)]
pub(in super::super) fn apply_medium_capture(
    current_effects: &mut crucible::ResolvedNetworkFrameEffects,
    pending_outputs: &mut [crucible::BackendNetworkOutput],
    reservations: &mut [NetworkMediumReservation],
    overlaps: &[usize],
    current: &NetworkMediumReservation,
    threshold_millionths: u64,
    action: &ResolvedBindingAction,
) -> Result<(), SchedulerError> {
    let mut contenders = overlaps
        .iter()
        .map(|index| {
            (
                Some(*index),
                reservations[*index].transmit_power_femtowatts,
                reservations[*index].opportunity,
            )
        })
        .chain(std::iter::once((
            None,
            current.transmit_power_femtowatts,
            current.opportunity,
        )))
        .collect::<Vec<_>>();
    contenders.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.2.cmp(&right.2)));
    let winner = contenders[0];
    let runner_up = contenders[1];
    let captures = u128::from(winner.1)
        .checked_mul(1_000_000)
        .is_some_and(|power| power >= u128::from(runner_up.1) * u128::from(threshold_millionths));
    for (index, _power, _opportunity) in contenders {
        if captures && index == winner.0 {
            if let Some(index) = index {
                reservations[index].terminal_collision_applied = true;
            }
            continue;
        }
        match index {
            Some(index) => {
                drop_medium_output(pending_outputs, &mut reservations[index], action)?;
            }
            None => current_effects.mark_drop(),
        }
    }
    Ok(())
}

pub(in super::super) fn network_state_machine_initial(
    topology: &crucible::model::WorldFaultTopology,
    machine: &FaultObjectId,
    action: &ResolvedBindingAction,
) -> Result<FaultObjectId, SchedulerError> {
    let declaration = topology.network_policy_artifact(machine).ok_or_else(|| {
        network_effect_application_error(action, "network state machine disappeared")
    })?;
    let crucible::model::NetworkPolicyArtifactKind::StateMachine { initial, .. } =
        &declaration.artifact
    else {
        return Err(network_effect_application_error(
            action,
            "network state machine changed type after admission",
        ));
    };
    Ok(initial.clone())
}

pub(in super::super) fn advance_network_state_machine(
    runtime: &mut NetworkStateMachineRuntime,
    topology: &crucible::model::WorldFaultTopology,
    machine: &FaultObjectId,
    event: &FaultObjectId,
    action: &ResolvedBindingAction,
    now: u64,
) -> Result<Option<u64>, SchedulerError> {
    let declaration = topology.network_policy_artifact(machine).ok_or_else(|| {
        network_effect_application_error(action, "network state machine disappeared")
    })?;
    let crucible::model::NetworkPolicyArtifactKind::StateMachine {
        initial,
        transitions,
        ..
    } = &declaration.artifact
    else {
        return Err(network_effect_application_error(
            action,
            "network state machine changed type after admission",
        ));
    };
    if runtime.transition_sequence != action.transition_sequence {
        *runtime = NetworkStateMachineRuntime {
            current: initial.clone(),
            pending: Vec::new(),
            transition_sequence: action.transition_sequence,
        };
    }
    let committed = runtime
        .pending
        .partition_point(|pending| pending.commit_nanos <= now);
    if committed > 0 {
        runtime.current = runtime.pending[committed - 1].state.clone();
        runtime.pending.drain(..committed);
    }
    let (from, service_start) = runtime.pending.last().map_or_else(
        || (runtime.current.clone(), now),
        |pending| (pending.state.clone(), pending.commit_nanos),
    );
    let edge = transitions
        .iter()
        .find(|edge| edge.from == from && &edge.event == event)
        .ok_or_else(|| {
            network_effect_application_error(
                action,
                "network state machine lacks its admitted exhaustive event edge",
            )
        })?;
    let commit = service_start.checked_add(edge.delay_nanos).ok_or_else(|| {
        network_effect_application_error(action, "network state transition coordinate overflowed")
    })?;
    if commit <= now {
        runtime.current = edge.to.clone();
        Ok(None)
    } else {
        if runtime.pending.len() >= 65_536 {
            return Err(network_effect_application_error(
                action,
                "network state-machine pending transition bound exceeded",
            ));
        }
        runtime.pending.push(NetworkPendingStateTransition {
            state: edge.to.clone(),
            commit_nanos: commit,
        });
        Ok(Some(commit))
    }
}

#[allow(clippy::too_many_arguments)]
pub(in super::super) fn stage_typed_network_response(
    scheduler: &SingleScheduler,
    pending_outputs: &mut Vec<crucible::BackendNetworkOutput>,
    topology: &crucible::model::WorldFaultTopology,
    rejected: &crucible::BackendNetworkOutput,
    route: &crucible::BackendNetworkRoute,
    response_id: &FaultObjectId,
    cause: ContentHash,
    frontier: VirtualTime,
) -> Result<Option<u64>, SchedulerError> {
    let declaration = topology
        .network_policy_artifact(response_id)
        .ok_or_else(|| SchedulerError::BoundaryViolation {
            message: format!("typed network response `{response_id}` disappeared after admission"),
        })?;
    let crucible::model::NetworkPolicyArtifactKind::TypedResponse(responses) =
        &declaration.artifact
    else {
        return Err(SchedulerError::BoundaryViolation {
            message: format!("network response `{response_id}` changed type after admission"),
        });
    };
    let mut selected = None;
    for response in &responses.responses {
        let specification = device_response_specification(response);
        match crucible_device::generate_network_response(&rejected.payload, &specification) {
            Ok(crucible_device::NetworkResponseOutcome::Frame(payload)) => {
                selected = Some((payload, response.headers.delay_nanos));
                break;
            }
            Ok(crucible_device::NetworkResponseOutcome::Suppressed) => return Ok(None),
            Err(crucible_device::NetworkResponseError::ProtocolMismatch) => {}
            Err(error) => {
                return Err(SchedulerError::BoundaryViolation {
                    message: format!("generate typed network response `{response_id}`: {error}"),
                });
            }
        }
    }
    let Some((payload, delay)) = selected else {
        return match responses.unmatched {
            crucible::model::NetworkPolicyUnmatchedResponse::Suppress => Ok(None),
            crucible::model::NetworkPolicyUnmatchedResponse::FailClosed => {
                Err(SchedulerError::BoundaryViolation {
                    message: format!(
                        "typed network response `{response_id}` has no variant for the rejected frame"
                    ),
                })
            }
        };
    };
    let mut fault_continuation = rejected
        .fault_continuation
        .generated_response(cause)
        .ok_or_else(|| SchedulerError::BoundaryViolation {
            message: format!(
                "typed network response `{response_id}` exceeds response-depth bound {}",
                crucible::model::HARD_NETWORK_RESPONSE_DEPTH
            ),
        })?;
    let delay = delay.map_or(0, |delay| delay.get());
    let release =
        frontier
            .ticks
            .checked_add(delay)
            .ok_or_else(|| SchedulerError::BoundaryViolation {
                message: format!("typed network response `{response_id}` delay overflowed"),
            })?;
    if release > frontier.ticks {
        fault_continuation.cursor_mut().defer_until(release, cause);
    }
    let emit_icount = scheduler.backend_effect_time(&route.destination, frontier)?;
    stage_pending_network_output(
        pending_outputs,
        crucible::BackendNetworkOutput {
            source: route.destination.clone(),
            destination: rejected.source.clone(),
            emit_icount: crucible::Icount {
                retired: emit_icount.ticks,
            },
            sequence: rejected.sequence,
            payload,
            route: None,
            fault_continuation,
        },
    )?;
    Ok((release > frontier.ticks).then_some(release))
}

pub(in super::super) fn device_response_specification(
    response: &crucible::model::NetworkPolicyTypedResponse,
) -> crucible_device::NetworkResponseSpecification {
    use crucible::model::NetworkPolicyTypedResponseKind as Model;
    let kind = match &response.response {
        Model::Icmpv4DestinationUnreachable {
            code,
            quote_payload_bytes,
        } => crucible_device::NetworkResponseKind::Icmpv4DestinationUnreachable {
            code: *code,
            quote_payload_bytes: *quote_payload_bytes,
        },
        Model::Icmpv4PacketTooBig {
            quote_payload_bytes,
            next_hop_mtu,
        } => crucible_device::NetworkResponseKind::Icmpv4PacketTooBig {
            quote_payload_bytes: *quote_payload_bytes,
            next_hop_mtu: *next_hop_mtu,
        },
        Model::Icmpv4TimeExceeded {
            code,
            quote_payload_bytes,
        } => crucible_device::NetworkResponseKind::Icmpv4TimeExceeded {
            code: *code,
            quote_payload_bytes: *quote_payload_bytes,
        },
        Model::Icmpv6DestinationUnreachable {
            code,
            quote_payload_bytes,
        } => crucible_device::NetworkResponseKind::Icmpv6DestinationUnreachable {
            code: *code,
            quote_payload_bytes: *quote_payload_bytes,
        },
        Model::Icmpv6PacketTooBig {
            quote_payload_bytes,
            next_hop_mtu,
        } => crucible_device::NetworkResponseKind::Icmpv6PacketTooBig {
            quote_payload_bytes: *quote_payload_bytes,
            next_hop_mtu: *next_hop_mtu,
        },
        Model::TcpReset => crucible_device::NetworkResponseKind::TcpReset,
        Model::OpaqueEthernet { bytes } => crucible_device::NetworkResponseKind::OpaqueEthernet {
            bytes: bytes.clone(),
        },
    };
    crucible_device::NetworkResponseSpecification {
        kind,
        headers: crucible_device::NetworkResponseHeaders {
            source_mac: response.headers.source_mac,
            source_ipv4: response.headers.source_ipv4,
            source_ipv6: response.headers.source_ipv6,
            hop_limit: response.headers.hop_limit,
            ipv4_identification: response.headers.ipv4_identification,
        },
    }
}

pub(in super::super) fn request_typed_response(
    selected: &mut Option<FaultObjectId>,
    response: &FaultObjectId,
    action: &ResolvedBindingAction,
) -> Result<(), SchedulerError> {
    if selected
        .as_ref()
        .is_some_and(|existing| existing != response)
    {
        return Err(network_effect_application_error(
            action,
            "simultaneous network rejections selected different typed responses",
        ));
    }
    *selected = Some(response.clone());
    Ok(())
}

pub(in super::super) fn apply_network_mtu(
    payload: &[u8],
    effects: &mut crucible::ResolvedNetworkFrameEffects,
    action: &ResolvedBindingAction,
    specification: &NetworkEffectSpecification,
    typed_response: &mut Option<FaultObjectId>,
) -> Result<Option<Vec<Vec<u8>>>, SchedulerError> {
    let NetworkEffectSpecification::Mtu {
        mtu_bytes,
        oversize,
        fragmentation_protocol,
        typed_error,
    } = specification
    else {
        return Err(network_effect_application_error(
            action,
            "MTU executor received non-MTU parameters",
        ));
    };
    let mtu = usize::try_from(mtu_bytes.get()).map_err(|_error| {
        network_effect_application_error(action, "MTU exceeds host address width")
    })?;
    if payload.len() <= mtu {
        return Ok(None);
    }
    match oversize {
        crucible::model::NetworkOversizeDisposition::Drop => {
            effects.mark_drop();
            Ok(None)
        }
        crucible::model::NetworkOversizeDisposition::Fragment => {
            let Some(crucible::model::NetworkFragmentationProtocol::EthernetIpv4) =
                fragmentation_protocol
            else {
                return Err(network_effect_application_error(
                    action,
                    "fragment disposition omitted its admitted protocol",
                ));
            };
            match crucible_device::fragment_ethernet_ipv4(payload, mtu)
                .map_err(|error| network_effect_application_error(action, &error.to_string()))?
            {
                crucible_device::Ipv4FragmentationOutcome::DontFragment => {
                    effects.mark_drop();
                    Ok(None)
                }
                crucible_device::Ipv4FragmentationOutcome::Frames(fragments) => Ok(Some(fragments)),
            }
        }
        crucible::model::NetworkOversizeDisposition::TypedError => {
            let response = typed_error.as_ref().ok_or_else(|| {
                network_effect_application_error(action, "typed MTU response omitted its artifact")
            })?;
            request_typed_response(typed_response, response, action)?;
            effects.mark_drop();
            Ok(None)
        }
    }
}

pub(in super::super) fn apply_network_pause_action(
    state: &mut NetworkEffectRuntimeState,
    action: &ResolvedBindingAction,
    class: &FaultObjectId,
    pause_nanos: Option<crucible::model::PositiveU64>,
    now: u64,
) -> Result<(), SchedulerError> {
    let key = NetworkEffectStateKey::from_action(action);
    if action.kind == BindingActionKind::RemovePersistent {
        state.backpressure.remove(&key);
        return Ok(());
    }
    let paused_until = pause_nanos
        .map(|duration| {
            action
                .coordinate
                .virtual_nanos
                .checked_add(duration.get())
                .ok_or_else(|| {
                    network_effect_application_error(action, "backpressure boundary overflowed")
                })
        })
        .transpose()?;
    if paused_until.is_some_and(|until| until <= now) {
        state.backpressure.remove(&key);
        return Ok(());
    }
    if let Some(existing) = state.backpressure.get(&key) {
        if action.transition_sequence < existing.transition_sequence {
            return Err(network_effect_application_error(
                action,
                "backpressure transition sequence regressed",
            ));
        }
        if action.transition_sequence == existing.transition_sequence {
            if existing.class != *class || existing.paused_until != paused_until {
                return Err(network_effect_application_error(
                    action,
                    "backpressure transition replay changed state",
                ));
            }
            return Ok(());
        }
    }
    state.backpressure.insert(
        key,
        NetworkPauseState {
            class: class.clone(),
            paused_until,
            transition_sequence: action.transition_sequence,
        },
    );
    Ok(())
}

pub(in super::super) fn next_network_pause_wakeup(
    pauses: &BTreeMap<NetworkEffectStateKey, NetworkPauseState>,
    now: u64,
) -> Option<u64> {
    pauses
        .values()
        .filter_map(|pause| pause.paused_until)
        .filter(|until| *until > now)
        .min()
}

pub(in super::super) fn apply_network_backpressure_transitions(
    state: &mut NetworkEffectRuntimeState,
    pending_outputs: &mut [crucible::BackendNetworkOutput],
    actions: &[ResolvedBindingAction],
    topology: &crucible::model::WorldFaultTopology,
    now: u64,
) -> Result<Option<u64>, SchedulerError> {
    let mut affected = BTreeSet::new();
    let expired = state
        .backpressure
        .iter()
        .filter(|(_key, pause)| pause.paused_until.is_some_and(|until| until <= now))
        .map(|(key, _pause)| key.clone())
        .collect::<Vec<_>>();
    for key in expired {
        affected.insert(key.target.clone());
        state.backpressure.remove(&key);
    }
    for action in actions {
        let EffectSpecification::Network(NetworkEffectSpecification::PauseBackpressure {
            class,
            pause_nanos,
        }) = action.effect.specification()
        else {
            continue;
        };
        affected.insert(action.target.clone());
        apply_network_pause_action(state, action, class, *pause_nanos, now)?;
    }
    for target in affected {
        let Some(queue) = state.queues.get_mut(&target) else {
            continue;
        };
        let configuration =
            queue
                .configuration
                .clone()
                .ok_or_else(|| SchedulerError::BoundaryViolation {
                    message: String::from("backpressure target queue omitted its configuration"),
                })?;
        retire_network_queue(queue, now, &configuration.owner)?;
        for reservation in &mut queue.reservations {
            reservation.ready_nanos = network_pause_boundary(
                &state.backpressure,
                &target,
                reservation.class.as_ref(),
                now,
            )
            .map_or(reservation.base_ready_nanos, |until| {
                reservation.base_ready_nanos.max(until)
            });
        }
        let parameters = configuration
            .discipline_parameters
            .as_ref()
            .map(|reference| {
                network_queue_discipline(topology, Some(reference), &configuration.owner)
            })
            .transpose()?;
        reschedule_network_queue(
            queue,
            pending_outputs,
            &configuration.owner,
            configuration.discipline,
            parameters,
            now,
            None,
        )?;
    }
    Ok(next_network_pause_wakeup(&state.backpressure, now))
}

#[allow(clippy::too_many_arguments)]
pub(in super::super) fn apply_network_queue_policy(
    state: &mut NetworkEffectRuntimeState,
    pending_outputs: &mut Vec<crucible::BackendNetworkOutput>,
    effects: &mut crucible::ResolvedNetworkFrameEffects,
    action: &ResolvedBindingAction,
    opportunity: &FaultOpportunity,
    scenario_seed: ContentHash,
    topology: &crucible::model::WorldFaultTopology,
    payload: &[u8],
    capacity_bytes: u64,
    capacity_frames: u64,
    discipline: crucible::model::NetworkQueueDiscipline,
    discipline_parameters: Option<&FaultObjectId>,
    overflow: crucible::model::NetworkQueueOverflow,
    overflow_response: Option<&FaultObjectId>,
    typed_response: &mut Option<FaultObjectId>,
    base_rate_bps: Option<u64>,
    service_curves: &[NetworkServiceCurveState],
    prerequisite_release: Option<u64>,
) -> Result<Option<u64>, SchedulerError> {
    let now = opportunity.coordinate().virtual_nanos;
    let payload_bytes = u64::try_from(payload.len()).map_err(|_error| {
        network_effect_application_error(action, "frame byte length exceeds queue width")
    })?;
    let parameters = discipline_parameters
        .map(|_reference| network_queue_discipline(topology, discipline_parameters, action))
        .transpose()?;
    let class = network_queue_class(payload, discipline, parameters, topology, action)?;
    let paused_until =
        network_pause_boundary(&state.backpressure, &action.target, class.as_ref(), now);
    let queue = state.queues.entry(action.target.clone()).or_default();
    let configuration = NetworkQueueConfiguration {
        owner: NetworkEffectStateKey::from_action(action),
        discipline,
        discipline_parameters: discipline_parameters.cloned(),
    };
    match &queue.configuration {
        Some(existing)
            if existing.discipline != configuration.discipline
                || existing.discipline_parameters != configuration.discipline_parameters =>
        {
            return Err(network_effect_application_error(
                action,
                "queue configuration changed without an explicit queue reset",
            ));
        }
        Some(_existing) => {}
        None => queue.configuration = Some(configuration),
    }
    retire_network_queue(queue, now, action)?;
    queue.service_cursor_nanos = queue.service_cursor_nanos.max(now);
    let occupied_bytes = queue
        .reservations
        .iter()
        .try_fold(0_u64, |total, reservation| {
            total.checked_add(reservation.bytes)
        })
        .ok_or_else(|| network_effect_application_error(action, "queue occupancy overflowed"))?;
    let occupied_frames = u64::try_from(queue.reservations.len()).map_err(|_error| {
        network_effect_application_error(action, "queue frame occupancy exceeds u64")
    })?;
    let mut hard_overflow = occupied_bytes
        .checked_add(payload_bytes)
        .is_none_or(|bytes| bytes > capacity_bytes)
        || occupied_frames
            .checked_add(1)
            .is_none_or(|frames| frames > capacity_frames);
    let mut early_drop = false;

    if discipline == crucible::model::NetworkQueueDiscipline::Red {
        let parameters = parameters.ok_or_else(|| {
            network_effect_application_error(action, "RED policy omitted discipline parameters")
        })?;
        let minimum = parameters.red_minimum_bytes.ok_or_else(|| {
            network_effect_application_error(action, "RED policy omitted its minimum threshold")
        })?;
        let maximum = parameters.red_maximum_bytes.ok_or_else(|| {
            network_effect_application_error(action, "RED policy omitted its maximum threshold")
        })?;
        let maximum_probability = parameters.red_maximum_probability.ok_or_else(|| {
            network_effect_application_error(action, "RED policy omitted its maximum probability")
        })?;
        let numerator = parameters.red_weight_numerator.ok_or_else(|| {
            network_effect_application_error(action, "RED policy omitted its EWMA numerator")
        })?;
        let denominator = parameters.red_weight_denominator.ok_or_else(|| {
            network_effect_application_error(action, "RED policy omitted its EWMA denominator")
        })?;
        let old_weight = denominator
            .get()
            .checked_sub(numerator.get())
            .ok_or_else(|| {
                network_effect_application_error(action, "RED EWMA numerator exceeds denominator")
            })?;
        let weighted_old = queue
            .red_average_bytes_q32
            .checked_mul(u128::from(old_weight))
            .ok_or_else(|| network_effect_application_error(action, "RED EWMA overflowed"))?;
        let weighted_sample = u128::from(occupied_bytes)
            .checked_shl(32)
            .and_then(|value| value.checked_mul(u128::from(numerator.get())))
            .ok_or_else(|| network_effect_application_error(action, "RED sample overflowed"))?;
        queue.red_average_bytes_q32 = weighted_old
            .checked_add(weighted_sample)
            .map(|value| value / u128::from(denominator.get()))
            .ok_or_else(|| network_effect_application_error(action, "RED EWMA overflowed"))?;
        let average_bytes = u64::try_from(queue.red_average_bytes_q32 >> 32).map_err(|_error| {
            network_effect_application_error(action, "RED average exceeds u64")
        })?;
        let probability = if average_bytes <= minimum {
            0
        } else if average_bytes >= maximum {
            maximum_probability.get()
        } else {
            let width = maximum - minimum;
            let offset = average_bytes - minimum;
            u32::try_from(
                u128::from(maximum_probability.get()) * u128::from(offset) / u128::from(width),
            )
            .map_err(|_error| {
                network_effect_application_error(action, "RED probability overflowed")
            })?
        };
        let probability =
            crucible::model::ProbabilityMillionths::new(probability).map_err(|_error| {
                network_effect_application_error(action, "RED probability is invalid")
            })?;
        early_drop = probability_fires(
            probability,
            network_effect_draw(scenario_seed, opportunity, action, "queue-red", 0),
        );
    }

    if hard_overflow || early_drop {
        match overflow {
            crucible::model::NetworkQueueOverflow::TailDrop => effects.mark_drop(),
            crucible::model::NetworkQueueOverflow::TypedError => {
                let response = overflow_response.ok_or_else(|| {
                    network_effect_application_error(
                        action,
                        "typed queue overflow omitted its response artifact",
                    )
                })?;
                request_typed_response(typed_response, response, action)?;
                effects.mark_drop();
                return Ok(None);
            }
            crucible::model::NetworkQueueOverflow::HeadDrop
            | crucible::model::NetworkQueueOverflow::KeyedDrop => {
                let mut ordinal = 0_u64;
                while hard_overflow || (early_drop && ordinal == 0) {
                    if queue.reservations.is_empty() {
                        effects.mark_drop();
                        break;
                    }
                    let victim = if overflow == crucible::model::NetworkQueueOverflow::HeadDrop {
                        0
                    } else {
                        usize::try_from(
                            network_effect_draw(
                                scenario_seed,
                                opportunity,
                                action,
                                "queue-victim",
                                ordinal,
                            ) % u64::try_from(queue.reservations.len()).map_err(|_error| {
                                network_effect_application_error(
                                    action,
                                    "queue candidate count exceeds u64",
                                )
                            })?,
                        )
                        .map_err(|_error| {
                            network_effect_application_error(
                                action,
                                "queue victim exceeds host width",
                            )
                        })?
                    };
                    let removed = queue.reservations.remove(victim);
                    pending_outputs.retain(|output| {
                        output.fault_continuation.cursor().queue_opportunity()
                            != Some(removed.opportunity)
                    });
                    ordinal = ordinal.checked_add(1).ok_or_else(|| {
                        network_effect_application_error(
                            action,
                            "queue eviction ordinal overflowed",
                        )
                    })?;
                    let remaining_bytes = queue
                        .reservations
                        .iter()
                        .try_fold(0_u64, |total, reservation| {
                            total.checked_add(reservation.bytes)
                        });
                    hard_overflow = remaining_bytes
                        .and_then(|bytes| bytes.checked_add(payload_bytes))
                        .is_none_or(|bytes| bytes > capacity_bytes)
                        || queue
                            .reservations
                            .len()
                            .checked_add(1)
                            .is_none_or(|frames| {
                                u64::try_from(frames)
                                    .ok()
                                    .is_none_or(|frames| frames > capacity_frames)
                            });
                }
            }
        }
    }
    if effects.is_dropped() || base_rate_bps.is_none() && service_curves.is_empty() {
        return Ok(None);
    }
    let payload_bits = payload_bytes.checked_mul(8).ok_or_else(|| {
        network_effect_application_error(action, "queue frame bit length overflowed")
    })?;
    let base_ready_nanos = prerequisite_release.unwrap_or(now).max(now);
    let ready_nanos = paused_until.map_or(base_ready_nanos, |pause| base_ready_nanos.max(pause));
    let remaining_nano_bits = u128::from(payload_bits)
        .checked_mul(1_000_000_000)
        .ok_or_else(|| network_effect_application_error(action, "queue demand overflowed"))?;
    queue.reservations.push(NetworkQueueReservation {
        enqueue_nanos: now,
        base_ready_nanos,
        ready_nanos,
        service_start_nanos: ready_nanos,
        finish_nanos: 0,
        bytes: payload_bytes,
        payload_bits,
        remaining_nano_bits,
        base_rate_bps,
        service_curves: service_curves.to_vec(),
        class,
        opportunity: opportunity.id(),
    });
    let finish = reschedule_network_queue(
        queue,
        pending_outputs,
        action,
        discipline,
        parameters,
        now,
        Some(opportunity.id()),
    )?
    .ok_or_else(|| {
        network_effect_application_error(action, "arriving queue reservation disappeared")
    })?;
    effects.mark_serialization_accounted();
    Ok(Some(finish))
}

pub(in super::super) fn network_queue_discipline<'a>(
    topology: &'a crucible::model::WorldFaultTopology,
    reference: Option<&FaultObjectId>,
    action: &impl NetworkEffectContext,
) -> Result<&'a crucible::model::NetworkPolicyQueueDiscipline, SchedulerError> {
    let reference = reference.ok_or_else(|| {
        network_effect_application_error(action, "queue discipline requires typed parameters")
    })?;
    let declaration = topology.network_policy_artifact(reference).ok_or_else(|| {
        network_effect_application_error(action, "queue discipline policy disappeared")
    })?;
    let crucible::model::NetworkPolicyArtifactKind::QueueDiscipline(parameters) =
        &declaration.artifact
    else {
        return Err(network_effect_application_error(
            action,
            "queue discipline policy changed type after admission",
        ));
    };
    Ok(parameters)
}

pub(in super::super) fn network_queue_class(
    payload: &[u8],
    discipline: crucible::model::NetworkQueueDiscipline,
    parameters: Option<&crucible::model::NetworkPolicyQueueDiscipline>,
    topology: &crucible::model::WorldFaultTopology,
    action: &ResolvedBindingAction,
) -> Result<Option<FaultObjectId>, SchedulerError> {
    if matches!(
        discipline,
        crucible::model::NetworkQueueDiscipline::Fifo
            | crucible::model::NetworkQueueDiscipline::Red
    ) {
        return Ok(None);
    }
    let parameters = parameters.ok_or_else(|| {
        network_effect_application_error(action, "class queue omitted discipline parameters")
    })?;
    let mut selected = None;
    for class in &parameters.classes {
        if network_packet_selector_matches(payload, topology, &class.selector, action)? {
            if selected.is_some() {
                return Err(network_effect_application_error(
                    action,
                    "frame matches multiple queue-class selectors",
                ));
            }
            selected = Some(class.class.clone());
        }
    }
    selected.map(Some).ok_or_else(|| {
        network_effect_application_error(action, "frame matches no queue-class selector")
    })
}

pub(in super::super) fn network_pause_boundary(
    pauses: &BTreeMap<NetworkEffectStateKey, NetworkPauseState>,
    target: &crucible::model::ResolvedFaultTarget,
    class: Option<&FaultObjectId>,
    now: u64,
) -> Option<u64> {
    let class = class?;
    pauses
        .iter()
        .filter(|(key, pause)| {
            &key.target == target
                && &pause.class == class
                && pause.paused_until.is_none_or(|until| now < until)
        })
        .map(|(_key, pause)| pause.paused_until.unwrap_or(u64::MAX))
        .max()
}

pub(in super::super) fn retire_network_queue(
    queue: &mut NetworkQueueState,
    now: u64,
    action: &impl NetworkEffectContext,
) -> Result<(), SchedulerError> {
    let mut completed = Vec::new();
    queue.reservations.retain(|reservation| {
        if reservation.finish_nanos <= now {
            completed.push((reservation.class.clone(), reservation.bytes));
            false
        } else {
            true
        }
    });
    for (class, bytes) in completed {
        if let Some(class) = class {
            let frames = queue
                .served_frames_by_class
                .entry(class.clone())
                .or_default();
            *frames = frames.checked_add(1).ok_or_else(|| {
                network_effect_application_error(action, "queue served-frame count overflowed")
            })?;
            let served = queue.served_bytes_by_class.entry(class).or_default();
            *served = served.checked_add(bytes).ok_or_else(|| {
                network_effect_application_error(action, "queue served-byte count overflowed")
            })?;
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(in super::super) fn reschedule_network_queue(
    queue: &mut NetworkQueueState,
    pending_outputs: &mut [crucible::BackendNetworkOutput],
    action: &impl NetworkEffectContext,
    discipline: crucible::model::NetworkQueueDiscipline,
    parameters: Option<&crucible::model::NetworkPolicyQueueDiscipline>,
    now: u64,
    arriving: Option<ContentHash>,
) -> Result<Option<u64>, SchedulerError> {
    let mut reservations = std::mem::take(&mut queue.reservations);
    let active_index = reservations
        .iter()
        .enumerate()
        .filter(|(_index, reservation)| {
            reservation.service_start_nanos <= now && now < reservation.finish_nanos
        })
        .min_by_key(|(_index, reservation)| reservation.service_start_nanos)
        .map(|(index, _reservation)| index);
    let mut active = active_index.map(|index| reservations.remove(index));
    if let Some(active) = active.as_mut() {
        let consumed = network_service_capacity(
            active.service_start_nanos,
            now,
            active.base_rate_bps,
            &active.service_curves,
            action,
        )?;
        active.remaining_nano_bits = active
            .remaining_nano_bits
            .checked_sub(consumed)
            .ok_or_else(|| {
                network_effect_application_error(
                    action,
                    "accounted service exceeds reservation demand",
                )
            })?;
        active.service_start_nanos = now;
    }
    if active
        .as_ref()
        .is_some_and(|active| active.ready_nanos > now)
        && let Some(active) = active.take()
    {
        reservations.push(active);
    }
    let mut projected_frames = queue.served_frames_by_class.clone();
    let mut projected_bytes = queue.served_bytes_by_class.clone();
    let mut cursor = now;
    let mut ordered = Vec::with_capacity(reservations.len() + usize::from(active.is_some()));
    if let Some(mut active) = active {
        active.service_start_nanos = now.max(active.ready_nanos);
        active.finish_nanos = network_service_finish_demand(
            active.service_start_nanos,
            active.remaining_nano_bits,
            active.base_rate_bps,
            &active.service_curves,
            action,
        )?;
        cursor = active.finish_nanos;
        add_projected_queue_service(&mut projected_frames, &mut projected_bytes, &active, action)?;
        ordered.push(active);
    }
    while !reservations.is_empty() {
        if reservations
            .iter()
            .all(|reservation| reservation.ready_nanos > cursor)
        {
            cursor = reservations
                .iter()
                .map(|reservation| reservation.ready_nanos)
                .min()
                .ok_or_else(|| {
                    network_effect_application_error(action, "queue readiness selection failed")
                })?;
        }
        let selected = (0..reservations.len())
            .filter(|index| reservations[*index].ready_nanos <= cursor)
            .min_by(|left, right| {
                compare_queue_candidates(
                    &reservations[*left],
                    &reservations[*right],
                    discipline,
                    parameters,
                    &projected_frames,
                    &projected_bytes,
                )
            })
            .ok_or_else(|| {
                network_effect_application_error(action, "queue candidate selection failed")
            })?;
        let mut reservation = reservations.remove(selected);
        let start = cursor.max(reservation.ready_nanos);
        if start == u64::MAX {
            reservation.service_start_nanos = u64::MAX;
            reservation.finish_nanos = u64::MAX;
            ordered.push(reservation);
            cursor = u64::MAX;
            continue;
        }
        reservation.service_start_nanos = start;
        reservation.finish_nanos = network_service_finish_demand(
            start,
            reservation.remaining_nano_bits,
            reservation.base_rate_bps,
            &reservation.service_curves,
            action,
        )?;
        cursor = reservation.finish_nanos;
        add_projected_queue_service(
            &mut projected_frames,
            &mut projected_bytes,
            &reservation,
            action,
        )?;
        ordered.push(reservation);
    }
    let finish = arriving.and_then(|arriving| {
        ordered
            .iter()
            .find(|reservation| reservation.opportunity == arriving)
            .map(|reservation| reservation.finish_nanos)
    });
    for reservation in &ordered {
        for output in pending_outputs.iter_mut().filter(|output| {
            output.fault_continuation.cursor().queue_opportunity() == Some(reservation.opportunity)
        }) {
            output
                .fault_continuation
                .cursor_mut()
                .reschedule_queue_until(reservation.opportunity, reservation.finish_nanos)
                .map_err(|error| network_effect_application_error(action, &error.to_string()))?;
        }
    }
    queue.service_cursor_nanos = cursor;
    queue.reservations = ordered;
    Ok(finish)
}

pub(in super::super) fn network_service_finish(
    start_nanos: u64,
    payload_bits: u64,
    base_rate_bps: Option<u64>,
    curves: &[NetworkServiceCurveState],
    action: &impl NetworkEffectContext,
) -> Result<u64, SchedulerError> {
    let remaining = u128::from(payload_bits)
        .checked_mul(1_000_000_000)
        .ok_or_else(|| network_effect_application_error(action, "service demand overflowed"))?;
    network_service_finish_demand(start_nanos, remaining, base_rate_bps, curves, action)
}

pub(in super::super) fn network_service_finish_demand(
    start_nanos: u64,
    mut remaining_nano_bits: u128,
    base_rate_bps: Option<u64>,
    curves: &[NetworkServiceCurveState],
    action: &impl NetworkEffectContext,
) -> Result<u64, SchedulerError> {
    if remaining_nano_bits == 0 {
        return Ok(start_nanos);
    }
    let mut cursor = start_nanos;
    loop {
        let mut rate = base_rate_bps;
        let mut next_breakpoint: Option<u64> = None;
        for curve in curves {
            let elapsed = cursor.checked_sub(curve.activation_nanos).ok_or_else(|| {
                network_effect_application_error(
                    action,
                    "service-curve activation follows queued service",
                )
            })?;
            let index = curve
                .segments
                .partition_point(|segment| segment.at_nanos <= elapsed)
                .checked_sub(1)
                .ok_or_else(|| {
                    network_effect_application_error(action, "service curve has no initial segment")
                })?;
            let curve_rate = curve.segments[index].rate_bps.get();
            rate = Some(rate.map_or(curve_rate, |current| current.min(curve_rate)));
            if let Some(segment) = curve.segments.get(index + 1) {
                let breakpoint = curve
                    .activation_nanos
                    .checked_add(segment.at_nanos)
                    .ok_or_else(|| {
                        network_effect_application_error(
                            action,
                            "service-curve breakpoint overflowed",
                        )
                    })?;
                next_breakpoint = match next_breakpoint {
                    Some(current) => Some(current.min(breakpoint)),
                    None => Some(breakpoint),
                };
            }
        }
        let rate = rate.ok_or_else(|| {
            network_effect_application_error(action, "queued service has no finite rate")
        })?;
        if let Some(breakpoint) = next_breakpoint {
            let interval = breakpoint.checked_sub(cursor).ok_or_else(|| {
                network_effect_application_error(action, "service breakpoint regressed")
            })?;
            let capacity = u128::from(interval)
                .checked_mul(u128::from(rate))
                .ok_or_else(|| {
                    network_effect_application_error(action, "service interval overflowed")
                })?;
            if remaining_nano_bits > capacity {
                remaining_nano_bits -= capacity;
                cursor = breakpoint;
                continue;
            }
        }
        let duration = ceil_ratio_u128(remaining_nano_bits, u128::from(rate))
            .and_then(|duration| u64::try_from(duration).ok())
            .ok_or_else(|| {
                network_effect_application_error(action, "service duration exceeds u64")
            })?;
        return cursor.checked_add(duration).ok_or_else(|| {
            network_effect_application_error(action, "service completion coordinate overflowed")
        });
    }
}

pub(in super::super) fn network_service_capacity(
    start_nanos: u64,
    end_nanos: u64,
    base_rate_bps: Option<u64>,
    curves: &[NetworkServiceCurveState],
    action: &impl NetworkEffectContext,
) -> Result<u128, SchedulerError> {
    if end_nanos < start_nanos {
        return Err(network_effect_application_error(
            action,
            "service accounting interval regressed",
        ));
    }
    let mut cursor = start_nanos;
    let mut capacity = 0_u128;
    while cursor < end_nanos {
        let mut rate = base_rate_bps;
        let mut next_breakpoint = end_nanos;
        for curve in curves {
            let elapsed = cursor.checked_sub(curve.activation_nanos).ok_or_else(|| {
                network_effect_application_error(
                    action,
                    "service-curve activation follows accounted service",
                )
            })?;
            let index = curve
                .segments
                .partition_point(|segment| segment.at_nanos <= elapsed)
                .checked_sub(1)
                .ok_or_else(|| {
                    network_effect_application_error(action, "service curve has no initial segment")
                })?;
            let curve_rate = curve.segments[index].rate_bps.get();
            rate = Some(rate.map_or(curve_rate, |current| current.min(curve_rate)));
            if let Some(segment) = curve.segments.get(index + 1) {
                next_breakpoint = next_breakpoint.min(
                    curve
                        .activation_nanos
                        .checked_add(segment.at_nanos)
                        .ok_or_else(|| {
                            network_effect_application_error(
                                action,
                                "service-curve breakpoint overflowed",
                            )
                        })?,
                );
            }
        }
        let rate = rate.ok_or_else(|| {
            network_effect_application_error(action, "accounted service has no finite rate")
        })?;
        let duration = next_breakpoint.checked_sub(cursor).ok_or_else(|| {
            network_effect_application_error(action, "service breakpoint regressed")
        })?;
        capacity = capacity
            .checked_add(
                u128::from(duration)
                    .checked_mul(u128::from(rate))
                    .ok_or_else(|| {
                        network_effect_application_error(action, "service capacity overflowed")
                    })?,
            )
            .ok_or_else(|| {
                network_effect_application_error(action, "service capacity overflowed")
            })?;
        cursor = next_breakpoint;
    }
    Ok(capacity)
}

pub(in super::super) fn add_projected_queue_service(
    frames: &mut BTreeMap<FaultObjectId, u64>,
    bytes: &mut BTreeMap<FaultObjectId, u64>,
    reservation: &NetworkQueueReservation,
    action: &impl NetworkEffectContext,
) -> Result<(), SchedulerError> {
    let Some(class) = &reservation.class else {
        return Ok(());
    };
    let frame_count = frames.entry(class.clone()).or_default();
    *frame_count = frame_count.checked_add(1).ok_or_else(|| {
        network_effect_application_error(action, "projected queue frame count overflowed")
    })?;
    let byte_count = bytes.entry(class.clone()).or_default();
    *byte_count = byte_count.checked_add(reservation.bytes).ok_or_else(|| {
        network_effect_application_error(action, "projected queue byte count overflowed")
    })?;
    Ok(())
}

pub(in super::super) fn compare_queue_candidates(
    left: &NetworkQueueReservation,
    right: &NetworkQueueReservation,
    discipline: crucible::model::NetworkQueueDiscipline,
    parameters: Option<&crucible::model::NetworkPolicyQueueDiscipline>,
    projected_frames: &BTreeMap<FaultObjectId, u64>,
    projected_bytes: &BTreeMap<FaultObjectId, u64>,
) -> std::cmp::Ordering {
    let fallback = || {
        (left.ready_nanos, left.enqueue_nanos, left.opportunity).cmp(&(
            right.ready_nanos,
            right.enqueue_nanos,
            right.opportunity,
        ))
    };
    if matches!(
        discipline,
        crucible::model::NetworkQueueDiscipline::Fifo
            | crucible::model::NetworkQueueDiscipline::Red
    ) {
        return fallback();
    }
    let (Some(parameters), Some(left_class), Some(right_class)) =
        (parameters, left.class.as_ref(), right.class.as_ref())
    else {
        return fallback();
    };
    let left_policy = parameters
        .classes
        .iter()
        .find(|class| &class.class == left_class);
    let right_policy = parameters
        .classes
        .iter()
        .find(|class| &class.class == right_class);
    let (Some(left_policy), Some(right_policy)) = (left_policy, right_policy) else {
        return fallback();
    };
    let order = match discipline {
        crucible::model::NetworkQueueDiscipline::StrictPriority => {
            left_policy.priority.cmp(&right_policy.priority)
        }
        crucible::model::NetworkQueueDiscipline::WeightedRoundRobin => {
            let left_load = u128::from(
                projected_frames
                    .get(left_class)
                    .copied()
                    .unwrap_or_default()
                    .saturating_add(1),
            );
            let right_load = u128::from(
                projected_frames
                    .get(right_class)
                    .copied()
                    .unwrap_or_default()
                    .saturating_add(1),
            );
            (left_load * u128::from(right_policy.weight.get()))
                .cmp(&(right_load * u128::from(left_policy.weight.get())))
        }
        crucible::model::NetworkQueueDiscipline::DeficitRoundRobin => {
            let left_load = u128::from(
                projected_bytes
                    .get(left_class)
                    .copied()
                    .unwrap_or_default()
                    .saturating_add(left.bytes),
            );
            let right_load = u128::from(
                projected_bytes
                    .get(right_class)
                    .copied()
                    .unwrap_or_default()
                    .saturating_add(right.bytes),
            );
            (left_load * u128::from(right_policy.quantum_bytes.get()))
                .cmp(&(right_load * u128::from(left_policy.quantum_bytes.get())))
        }
        crucible::model::NetworkQueueDiscipline::Fifo
        | crucible::model::NetworkQueueDiscipline::Red => std::cmp::Ordering::Equal,
    };
    order
        .then_with(|| left_class.cmp(right_class))
        .then_with(fallback)
}

pub(in super::super) fn latest_wakeup(current: Option<u64>, candidate: Option<u64>) -> Option<u64> {
    match (current, candidate) {
        (Some(current), Some(candidate)) => Some(current.max(candidate)),
        (Some(current), None) => Some(current),
        (None, candidate) => candidate,
    }
}

#[allow(clippy::too_many_arguments)]
pub(in super::super) fn apply_network_token_bucket(
    state: &mut NetworkEffectRuntimeState,
    action: &ResolvedBindingAction,
    opportunity: &FaultOpportunity,
    payload_bytes: usize,
    rate_bps: u64,
    burst_bits: u64,
    initial_bits: u64,
) -> Result<u64, SchedulerError> {
    let payload_bits = u64::try_from(payload_bytes)
        .ok()
        .and_then(|bytes| bytes.checked_mul(8))
        .ok_or_else(|| network_effect_application_error(action, "frame bit length overflowed"))?;
    if payload_bits > burst_bits {
        return Err(network_effect_application_error(
            action,
            "frame exceeds token-bucket burst capacity",
        ));
    }
    let now = opportunity.coordinate().virtual_nanos;
    let token_scale = 1_000_000_000_u128;
    let capacity = u128::from(burst_bits)
        .checked_mul(token_scale)
        .ok_or_else(|| network_effect_application_error(action, "token capacity overflowed"))?;
    let cost = u128::from(payload_bits)
        .checked_mul(token_scale)
        .ok_or_else(|| network_effect_application_error(action, "token cost overflowed"))?;
    let key = NetworkEffectStateKey::from_action(action);
    let bucket = state
        .token_buckets
        .entry(key)
        .or_insert_with(|| NetworkTokenBucketState {
            tokens_nano_bits: u128::from(initial_bits) * token_scale,
            last_refill_nanos: action.coordinate.virtual_nanos,
            transition_sequence: action.transition_sequence,
        });
    if bucket.transition_sequence != action.transition_sequence {
        *bucket = NetworkTokenBucketState {
            tokens_nano_bits: u128::from(initial_bits) * token_scale,
            last_refill_nanos: action.coordinate.virtual_nanos,
            transition_sequence: action.transition_sequence,
        };
    }
    let service_base = bucket.last_refill_nanos.max(now);
    if now >= bucket.last_refill_nanos {
        let added = u128::from(now - bucket.last_refill_nanos)
            .checked_mul(u128::from(rate_bps))
            .ok_or_else(|| network_effect_application_error(action, "token refill overflowed"))?;
        bucket.tokens_nano_bits = bucket.tokens_nano_bits.saturating_add(added).min(capacity);
        bucket.last_refill_nanos = now;
    }
    if bucket.tokens_nano_bits >= cost {
        bucket.tokens_nano_bits -= cost;
        return Ok(service_base - now);
    }
    let deficit = cost - bucket.tokens_nano_bits;
    let delay = ceil_ratio_u128(deficit, u128::from(rate_bps))
        .and_then(|value| u64::try_from(value).ok())
        .ok_or_else(|| network_effect_application_error(action, "token wait exceeds u64"))?;
    let produced = u128::from(delay)
        .checked_mul(u128::from(rate_bps))
        .ok_or_else(|| network_effect_application_error(action, "token service overflowed"))?;
    bucket.tokens_nano_bits = produced - deficit;
    bucket.last_refill_nanos = service_base
        .checked_add(delay)
        .ok_or_else(|| network_effect_application_error(action, "token release overflowed"))?;
    bucket
        .last_refill_nanos
        .checked_sub(now)
        .ok_or_else(|| network_effect_application_error(action, "token delay underflowed"))
}

pub(in super::super) fn ceil_ratio_u128(numerator: u128, denominator: u128) -> Option<u128> {
    numerator
        .checked_add(denominator.checked_sub(1)?)
        .map(|value| value / denominator)
}

#[allow(clippy::too_many_arguments)]
pub(in super::super) fn apply_network_burst_error(
    payload: &mut [u8],
    effects: &mut crucible::ResolvedNetworkFrameEffects,
    state: &mut NetworkEffectRuntimeState,
    action: &ResolvedBindingAction,
    opportunity: &FaultOpportunity,
    scenario_seed: ContentHash,
    topology: &crucible::model::WorldFaultTopology,
    good_to_bad: crucible::model::ProbabilityMillionths,
    bad_to_good: crucible::model::ProbabilityMillionths,
    parameters: &FaultObjectId,
) -> Result<(), SchedulerError> {
    let declaration = topology
        .network_policy_artifact(parameters)
        .ok_or_else(|| {
            network_effect_application_error(action, "burst-error policy disappeared")
        })?;
    let crucible::model::NetworkPolicyArtifactKind::ErrorStateTable {
        good,
        bad,
        initial,
        states,
    } = &declaration.artifact
    else {
        return Err(network_effect_application_error(
            action,
            "burst-error policy changed type after admission",
        ));
    };
    if states.len() != 2 {
        return Err(network_effect_application_error(
            action,
            "burst-error policy must contain exactly good and bad states",
        ));
    }
    let key = NetworkEffectStateKey::from_action(action);
    let current = state
        .burst_states
        .entry(key)
        .or_insert_with(|| initial.clone());
    let transition = if current == bad {
        bad_to_good
    } else if current == good {
        good_to_bad
    } else {
        return Err(network_effect_application_error(
            action,
            "burst-error current state is neither good nor bad",
        ));
    };
    if probability_fires(
        transition,
        network_effect_draw(scenario_seed, opportunity, action, "burst-transition", 0),
    ) {
        *current = if current == bad {
            good.clone()
        } else {
            bad.clone()
        };
    }
    let selected = states
        .iter()
        .find(|candidate| candidate.state == *current)
        .ok_or_else(|| network_effect_application_error(action, "burst-error state disappeared"))?;
    if probability_fires(
        selected.loss,
        network_effect_draw(scenario_seed, opportunity, action, "burst-loss", 0),
    ) {
        effects.mark_drop();
    }
    if !payload.is_empty()
        && probability_fires(
            selected.corruption,
            network_effect_draw(scenario_seed, opportunity, action, "burst-corruption", 0),
        )
    {
        let transform = selected.corruption_transform.as_ref().ok_or_else(|| {
            network_effect_application_error(action, "burst corruption omitted its transform")
        })?;
        let bytes = network_byte_template(topology, transform, action)?;
        if bytes.is_empty() {
            return Err(network_effect_application_error(
                action,
                "burst corruption transform is empty",
            ));
        }
        for (index, byte) in payload.iter_mut().enumerate() {
            *byte ^= bytes[index % bytes.len()];
        }
    }
    Ok(())
}
