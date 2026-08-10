//! Custody routing, bundle service, and deterministic payload mutation.
//!
//! Contact-graph reservations and packet edits are applied to staged network
//! state so rejection leaves both bytes and capacity accounting unchanged.

use super::*;

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct NetworkCustodyApplication {
    pub(super) defer_until: Option<u64>,
    pub(super) repeat_phase_on_resume: bool,
}

pub(in super::super) fn network_bundle_identity(
    opportunity: &FaultOpportunity,
    action: &ResolvedBindingAction,
    priority: crucible::model::NetworkBundlePriority,
) -> Result<NetworkBundleIdentity, SchedulerError> {
    let OpportunityPayload::NetworkFrame {
        producer,
        destination,
        producer_sequence,
        protocol_expansion_path,
        generated_response_depth,
        generated_response_cause,
        forwarding_mutation_path,
        length_bytes,
        payload_digest,
    } = opportunity.payload()
    else {
        return Err(network_effect_application_error(
            action,
            "custody queue received a non-frame opportunity",
        ));
    };
    Ok(NetworkBundleIdentity {
        producer: producer.clone(),
        destination: destination.clone(),
        producer_sequence: *producer_sequence,
        protocol_expansion_path: protocol_expansion_path.clone(),
        generated_response_depth: *generated_response_depth,
        generated_response_cause: *generated_response_cause,
        forwarding_mutation_path: forwarding_mutation_path.clone(),
        length_bytes: *length_bytes,
        payload_digest: *payload_digest,
        priority,
    })
}

pub(in super::super) fn contact_traffic_bounds(
    interval: &crucible::model::NetworkPolicyContactInterval,
    action: &ResolvedBindingAction,
) -> Result<(u64, u64), SchedulerError> {
    let open = interval
        .start_nanos
        .checked_add(interval.acquisition_nanos)
        .ok_or_else(|| {
            network_effect_application_error(action, "contact acquisition overflowed")
        })?;
    let end = interval
        .end_nanos
        .checked_sub(interval.teardown_nanos)
        .ok_or_else(|| network_effect_application_error(action, "contact teardown underflowed"))?;
    Ok((open, end))
}

#[allow(clippy::too_many_arguments)]
pub(in super::super) fn reserve_network_contact_service(
    state: &mut NetworkEffectRuntimeState,
    topology: &crucible::model::WorldFaultTopology,
    plan: &FaultObjectId,
    interval: &crucible::model::NetworkPolicyContactInterval,
    producer: &FaultObjectId,
    destination: &FaultObjectId,
    now: u64,
    payload_bytes: u64,
    opportunity: ContentHash,
    action: &ResolvedBindingAction,
) -> Result<Option<(u64, [u8; 32])>, SchedulerError> {
    prune_network_contact_services(state, now);
    let (open, traffic_end) = contact_traffic_bounds(interval, action)?;
    if &interval.source != producer
        || &interval.destination != destination
        || now < open
        || now >= traffic_end
    {
        return Ok(None);
    }
    let capacity = topology
        .network_policy_artifact(&interval.capacity_profile)
        .ok_or_else(|| network_effect_application_error(action, "contact capacity disappeared"))?;
    let crucible::model::NetworkPolicyArtifactKind::ServiceCurve { segments } = &capacity.artifact
    else {
        return Err(network_effect_application_error(
            action,
            "contact capacity changed type after admission",
        ));
    };
    let key = NetworkContactServiceKey {
        plan: plan.clone(),
        contact: interval.contact.clone(),
        service_resource: interval.service_resource.clone(),
        source: producer.clone(),
        destination: destination.clone(),
        start_nanos: interval.start_nanos,
        end_nanos: interval.end_nanos,
    };
    let identity = network_contact_service_identity(&key);
    let start = state
        .contact_services
        .get(&key)
        .map_or(now.max(open), |service| {
            now.max(open).max(service.service_cursor_nanos)
        });
    if start >= traffic_end {
        return Ok(None);
    }
    let bits = payload_bytes
        .checked_mul(8)
        .ok_or_else(|| network_effect_application_error(action, "contact frame size overflowed"))?;
    let finish = network_service_finish(
        start,
        bits,
        None,
        &[NetworkServiceCurveState {
            activation_nanos: interval.start_nanos,
            segments: segments.as_slice().to_vec(),
        }],
        action,
    )?;
    if finish > traffic_end {
        return Ok(None);
    }
    admit_network_contact_service_keys(state, &BTreeSet::from([key.clone()]), action)?;
    if network_contact_reservation_count(state)
        .and_then(|count| count.checked_add(1))
        .is_none_or(|count| count > HARD_CONTACT_SERVICE_RESERVATIONS)
    {
        return Err(network_effect_application_error(
            action,
            "contact reservation ledger exceeds 262,144 live entries",
        ));
    }
    let (next_served_bundles, next_served_bytes) = state
        .contact_services
        .get(&key)
        .map_or(Some((1, payload_bytes)), |service| {
            service
                .served_bundles
                .checked_add(1)
                .zip(service.served_bytes.checked_add(payload_bytes))
        })
        .ok_or_else(|| {
            network_effect_application_error(
                action,
                "contact service counters overflow before direct reservation",
            )
        })?;
    let key_start = key.start_nanos;
    let service = state
        .contact_services
        .entry(key)
        .or_insert_with(|| NetworkContactServiceState {
            settled_cursor_nanos: key_start,
            service_cursor_nanos: key_start,
            ..NetworkContactServiceState::default()
        });
    service.service_cursor_nanos = finish;
    service.served_bundles = next_served_bundles;
    service.served_bytes = next_served_bytes;
    service.reservations.push(NetworkContactServiceReservation {
        custody_owner: None,
        opportunity,
        start_nanos: start,
        finish_nanos: finish,
        arrival_nanos: finish,
        bytes: payload_bytes,
    });
    service.reservations.sort_by(|left, right| {
        (left.start_nanos, left.finish_nanos, left.opportunity).cmp(&(
            right.start_nanos,
            right.finish_nanos,
            right.opportunity,
        ))
    });
    Ok(Some((finish, identity)))
}

#[derive(Clone, Debug)]
pub(super) struct NetworkContactRouteLabel {
    node: FaultObjectId,
    arrival_nanos: u64,
    cost: u64,
    interval_indexes: Vec<usize>,
    contact_ids: Vec<FaultObjectId>,
    visited_nodes: BTreeSet<FaultObjectId>,
}

#[derive(Clone, Debug)]
pub(super) struct NetworkContactRouteReservation {
    first_start_nanos: u64,
    finish_nanos: u64,
    contacts: Vec<FaultObjectId>,
    identities: Vec<[u8; 32]>,
}

pub(super) type NetworkContactServicePreview = (u64, u64, u64, NetworkContactServiceKey, [u8; 32]);

pub(in super::super) fn preview_network_contact_service(
    state: &NetworkEffectRuntimeState,
    topology: &crucible::model::WorldFaultTopology,
    plan: &FaultObjectId,
    interval: &crucible::model::NetworkPolicyContactInterval,
    earliest_nanos: u64,
    payload_bytes: u64,
    action: &ResolvedBindingAction,
) -> Result<Option<NetworkContactServicePreview>, SchedulerError> {
    let (open, traffic_end) = contact_traffic_bounds(interval, action)?;
    let key = NetworkContactServiceKey {
        plan: plan.clone(),
        contact: interval.contact.clone(),
        service_resource: interval.service_resource.clone(),
        source: interval.source.clone(),
        destination: interval.destination.clone(),
        start_nanos: interval.start_nanos,
        end_nanos: interval.end_nanos,
    };
    let start = state
        .contact_services
        .get(&key)
        .map_or(earliest_nanos.max(open), |service| {
            earliest_nanos.max(open).max(service.service_cursor_nanos)
        });
    if start >= traffic_end {
        return Ok(None);
    }
    let capacity = topology
        .network_policy_artifact(&interval.capacity_profile)
        .ok_or_else(|| network_effect_application_error(action, "contact capacity disappeared"))?;
    let crucible::model::NetworkPolicyArtifactKind::ServiceCurve { segments } = &capacity.artifact
    else {
        return Err(network_effect_application_error(
            action,
            "contact capacity changed type after admission",
        ));
    };
    let bits = payload_bytes
        .checked_mul(8)
        .ok_or_else(|| network_effect_application_error(action, "contact frame size overflowed"))?;
    let finish = network_service_finish(
        start,
        bits,
        None,
        &[NetworkServiceCurveState {
            activation_nanos: interval.start_nanos,
            segments: segments.as_slice().to_vec(),
        }],
        action,
    )?;
    if finish > traffic_end {
        return Ok(None);
    }
    let arrival = finish
        .checked_add(interval.routing_propagation_nanos)
        .ok_or_else(|| {
            network_effect_application_error(action, "contact propagation overflowed")
        })?;
    let identity = network_contact_service_identity(&key);
    Ok(Some((start, finish, arrival, key, identity)))
}

#[allow(clippy::too_many_arguments)]
pub(in super::super) fn reserve_network_contact_route(
    state: &mut NetworkEffectRuntimeState,
    topology: &crucible::model::WorldFaultTopology,
    plan: &FaultObjectId,
    intervals: &[crucible::model::NetworkPolicyContactInterval],
    producer: &FaultObjectId,
    destination: &FaultObjectId,
    now: u64,
    expiry_nanos: u64,
    payload_bytes: u64,
    max_visited_hops: u32,
    owner: &NetworkEffectStateKey,
    opportunity: ContentHash,
    commit: bool,
    action: &ResolvedBindingAction,
) -> Result<Option<NetworkContactRouteReservation>, SchedulerError> {
    const HARD_CONTACT_ROUTE_LABELS: usize = 262_144;
    let mut visited_nodes = BTreeSet::new();
    visited_nodes.insert(producer.clone());
    let mut frontier = vec![NetworkContactRouteLabel {
        node: producer.clone(),
        arrival_nanos: now,
        cost: 0,
        interval_indexes: Vec::new(),
        contact_ids: Vec::new(),
        visited_nodes,
    }];
    let mut expanded = 0_usize;
    let selected = loop {
        frontier.sort_by(|left, right| {
            (left.cost, &left.contact_ids, left.arrival_nanos, &left.node).cmp(&(
                right.cost,
                &right.contact_ids,
                right.arrival_nanos,
                &right.node,
            ))
        });
        if frontier.is_empty() {
            break None;
        }
        let label = frontier.remove(0);
        if &label.node == destination {
            break Some(label);
        }
        if label.interval_indexes.len()
            >= usize::try_from(max_visited_hops).map_err(|_error| {
                network_effect_application_error(action, "contact hop bound exceeds usize")
            })?
        {
            continue;
        }
        for (index, interval) in intervals.iter().enumerate() {
            if interval.source != label.node || label.visited_nodes.contains(&interval.destination)
            {
                continue;
            }
            let Some((_start, _finish, arrival, _key, _identity)) =
                preview_network_contact_service(
                    state,
                    topology,
                    plan,
                    interval,
                    label.arrival_nanos,
                    payload_bytes,
                    action,
                )?
            else {
                continue;
            };
            if arrival > expiry_nanos {
                continue;
            }
            let mut candidate = label.clone();
            candidate.node = interval.destination.clone();
            candidate.arrival_nanos = arrival;
            candidate.cost = candidate
                .cost
                .checked_add(interval.route_cost.get())
                .ok_or_else(|| {
                    network_effect_application_error(action, "contact route cost overflowed")
                })?;
            candidate.interval_indexes.push(index);
            candidate.contact_ids.push(interval.contact.clone());
            candidate.visited_nodes.insert(interval.destination.clone());
            frontier.push(candidate);
            expanded = expanded.checked_add(1).ok_or_else(|| {
                network_effect_application_error(action, "contact route label count overflowed")
            })?;
            if expanded > HARD_CONTACT_ROUTE_LABELS {
                return Err(network_effect_application_error(
                    action,
                    "contact route search exceeds 262,144 labels",
                ));
            }
        }
    };
    let Some(selected) = selected else {
        return Ok(None);
    };
    if commit {
        let keys = selected
            .interval_indexes
            .iter()
            .map(|index| {
                let interval = &intervals[*index];
                NetworkContactServiceKey {
                    plan: plan.clone(),
                    contact: interval.contact.clone(),
                    service_resource: interval.service_resource.clone(),
                    source: interval.source.clone(),
                    destination: interval.destination.clone(),
                    start_nanos: interval.start_nanos,
                    end_nanos: interval.end_nanos,
                }
            })
            .collect::<BTreeSet<_>>();
        admit_network_contact_service_keys(state, &keys, action)?;
    }
    if commit
        && network_contact_reservation_count(state)
            .and_then(|count| count.checked_add(selected.interval_indexes.len()))
            .is_none_or(|count| count > HARD_CONTACT_SERVICE_RESERVATIONS)
    {
        return Err(network_effect_application_error(
            action,
            "contact reservation ledger exceeds 262,144 live entries",
        ));
    }
    if commit {
        for index in &selected.interval_indexes {
            let interval = &intervals[*index];
            let key = NetworkContactServiceKey {
                plan: plan.clone(),
                contact: interval.contact.clone(),
                service_resource: interval.service_resource.clone(),
                source: interval.source.clone(),
                destination: interval.destination.clone(),
                start_nanos: interval.start_nanos,
                end_nanos: interval.end_nanos,
            };
            if state.contact_services.get(&key).is_some_and(|service| {
                service.served_bundles.checked_add(1).is_none()
                    || service.served_bytes.checked_add(payload_bytes).is_none()
            }) {
                return Err(network_effect_application_error(
                    action,
                    "contact service counters overflow during atomic route reservation",
                ));
            }
        }
    }
    let mut cursor = now;
    let mut first_start_nanos = None;
    let mut identities = Vec::with_capacity(selected.interval_indexes.len());
    for index in &selected.interval_indexes {
        let interval = &intervals[*index];
        let Some((start, finish, arrival, key, identity)) = preview_network_contact_service(
            state,
            topology,
            plan,
            interval,
            cursor,
            payload_bytes,
            action,
        )?
        else {
            return Err(network_effect_application_error(
                action,
                "selected contact route changed during atomic reservation",
            ));
        };
        first_start_nanos.get_or_insert(start);
        if commit {
            let key_start = key.start_nanos;
            let service =
                state
                    .contact_services
                    .entry(key)
                    .or_insert_with(|| NetworkContactServiceState {
                        settled_cursor_nanos: key_start,
                        service_cursor_nanos: key_start,
                        ..NetworkContactServiceState::default()
                    });
            service.service_cursor_nanos = finish;
            service.served_bundles = service.served_bundles.checked_add(1).ok_or_else(|| {
                network_effect_application_error(action, "contact served-bundle count overflowed")
            })?;
            service.served_bytes =
                service
                    .served_bytes
                    .checked_add(payload_bytes)
                    .ok_or_else(|| {
                        network_effect_application_error(
                            action,
                            "contact served-byte count overflowed",
                        )
                    })?;
            service.reservations.push(NetworkContactServiceReservation {
                custody_owner: Some(owner.clone()),
                opportunity,
                start_nanos: start,
                finish_nanos: finish,
                arrival_nanos: arrival,
                bytes: payload_bytes,
            });
            service.reservations.sort_by(|left, right| {
                (left.start_nanos, left.finish_nanos, left.opportunity).cmp(&(
                    right.start_nanos,
                    right.finish_nanos,
                    right.opportunity,
                ))
            });
        }
        identities.push(identity);
        cursor = arrival;
    }
    Ok(Some(NetworkContactRouteReservation {
        first_start_nanos: first_start_nanos.ok_or_else(|| {
            network_effect_application_error(action, "selected contact route is empty")
        })?,
        finish_nanos: selected.arrival_nanos,
        contacts: selected.contact_ids,
        identities,
    }))
}

pub(in super::super) fn contact_graph_has_path(
    intervals: &[crucible::model::NetworkPolicyContactInterval],
    producer: &FaultObjectId,
    destination: &FaultObjectId,
    max_visited_hops: u32,
) -> bool {
    let mut frontier = vec![(producer.clone(), 0_u32)];
    let mut visited = BTreeSet::new();
    visited.insert((producer.clone(), 0_u32));
    while let Some((node, hops)) = frontier.pop() {
        if &node == destination {
            return true;
        }
        if hops == max_visited_hops {
            continue;
        }
        for interval in intervals.iter().filter(|interval| interval.source == node) {
            let candidate = (interval.destination.clone(), hops.saturating_add(1));
            if visited.insert(candidate.clone()) {
                frontier.push(candidate);
            }
        }
    }
    false
}

#[allow(clippy::too_many_arguments)]
pub(in super::super) fn apply_network_custody_queue(
    payload: &[u8],
    effects: &mut crucible::ResolvedNetworkFrameEffects,
    state: &mut NetworkEffectRuntimeState,
    pending_outputs: &mut Vec<crucible::BackendNetworkOutput>,
    topology: &crucible::model::WorldFaultTopology,
    action: &ResolvedBindingAction,
    opportunity: &FaultOpportunity,
    capacity_bytes: u64,
    capacity_bundles: u64,
    expiry_duration: u64,
    custody_policy: &FaultObjectId,
    route_contact_plan: &FaultObjectId,
    priority: crucible::model::NetworkBundlePriority,
    max_visited_hops: u32,
    typed_response: &mut Option<FaultObjectId>,
) -> Result<NetworkCustodyApplication, SchedulerError> {
    let now = opportunity.coordinate().virtual_nanos;
    prune_network_contact_services(state, now);
    let bundle = network_bundle_identity(opportunity, action, priority)?;
    let payload_bytes = u64::try_from(payload.len()).map_err(|_error| {
        network_effect_application_error(action, "custody bundle length exceeds u64")
    })?;
    if payload_bytes != bundle.length_bytes {
        return Err(network_effect_application_error(
            action,
            "custody opportunity length differs from the frame payload",
        ));
    }
    let policy = topology
        .network_policy_artifact(custody_policy)
        .ok_or_else(|| {
            network_effect_application_error(action, "custody overflow policy disappeared")
        })?;
    let crucible::model::NetworkPolicyArtifactKind::Overflow {
        disposition,
        timeout_nanos,
        typed_error,
    } = &policy.artifact
    else {
        return Err(network_effect_application_error(
            action,
            "custody overflow policy changed type after admission",
        ));
    };
    let plan = topology
        .network_policy_artifact(route_contact_plan)
        .ok_or_else(|| {
            network_effect_application_error(action, "custody contact plan disappeared")
        })?;
    let crucible::model::NetworkPolicyArtifactKind::ContactPlan { intervals } = &plan.artifact
    else {
        return Err(network_effect_application_error(
            action,
            "custody contact plan changed type after admission",
        ));
    };
    let owner = NetworkEffectStateKey::from_action(action);
    let configuration = NetworkCustodyConfiguration {
        owner: owner.clone(),
        capacity_bytes,
        capacity_bundles,
        expiry_nanos: expiry_duration,
        custody_policy: custody_policy.clone(),
        route_contact_plan: route_contact_plan.clone(),
        priority,
        max_visited_hops,
    };
    let queue = state.custody_queues.entry(owner.clone()).or_default();
    match &queue.configuration {
        Some(existing) if existing != &configuration => {
            return Err(network_effect_application_error(
                action,
                "custody queue configuration changed without removal",
            ));
        }
        Some(_existing) => {}
        None => queue.configuration = Some(configuration),
    }

    if let Some(index) = queue
        .overflow_timeouts
        .iter()
        .position(|timeout| timeout.bundle == bundle)
    {
        let timeout = queue.overflow_timeouts.remove(index);
        if now < timeout.deadline_nanos {
            return Err(network_effect_application_error(
                action,
                "custody timeout resumed before its deadline",
            ));
        }
        queue.dropped_bundles = queue.dropped_bundles.checked_add(1).ok_or_else(|| {
            network_effect_application_error(action, "custody drop count overflowed")
        })?;
        effects.mark_drop();
        return Ok(NetworkCustodyApplication::default());
    }

    let existing = queue
        .reservations
        .iter()
        .position(|reservation| reservation.bundle == bundle)
        .map(|index| queue.reservations.remove(index));
    let was_existing = existing.is_some();
    let (enqueue_nanos, expiry_nanos, _prior_contact_path, prior_path_committed) =
        if let Some(existing) = existing {
            if now < existing.release_nanos {
                return Err(network_effect_application_error(
                    action,
                    "custody bundle resumed before its release coordinate",
                ));
            }
            (
                existing.enqueue_nanos,
                existing.expiry_nanos,
                existing.contact_path,
                existing.contact_path_committed,
            )
        } else {
            let expiry_nanos = now.checked_add(expiry_duration).ok_or_else(|| {
                network_effect_application_error(action, "custody expiry overflowed")
            })?;
            (now, expiry_nanos, Vec::new(), false)
        };
    if was_existing && prior_path_committed {
        queue.released_bundles = queue.released_bundles.checked_add(1).ok_or_else(|| {
            network_effect_application_error(action, "custody release count overflowed")
        })?;
        return Ok(NetworkCustodyApplication::default());
    }
    if now >= expiry_nanos {
        queue.expired_bundles = queue.expired_bundles.checked_add(1).ok_or_else(|| {
            network_effect_application_error(action, "custody expiry count overflowed")
        })?;
        queue.dropped_bundles = queue.dropped_bundles.checked_add(1).ok_or_else(|| {
            network_effect_application_error(action, "custody drop count overflowed")
        })?;
        effects.mark_drop();
        return Ok(NetworkCustodyApplication::default());
    }

    if !was_existing {
        let (custody_queues, contact_services) =
            (&mut state.custody_queues, &mut state.contact_services);
        let queue = custody_queues
            .get_mut(&owner)
            .ok_or_else(|| network_effect_application_error(action, "custody queue disappeared"))?;
        let mut occupied_bytes = queue
            .reservations
            .iter()
            .try_fold(0_u64, |total, reservation| {
                total.checked_add(reservation.bytes)
            })
            .ok_or_else(|| {
                network_effect_application_error(action, "custody occupancy overflowed")
            })?;
        let mut over_capacity = occupied_bytes
            .checked_add(payload_bytes)
            .is_none_or(|bytes| bytes > capacity_bytes)
            || u64::try_from(queue.reservations.len())
                .ok()
                .and_then(|count| count.checked_add(1))
                .is_none_or(|count| count > capacity_bundles);
        if over_capacity {
            match disposition {
                crucible::model::NetworkPolicyOverflow::DropNewest => {
                    queue.dropped_bundles =
                        queue.dropped_bundles.checked_add(1).ok_or_else(|| {
                            network_effect_application_error(
                                action,
                                "custody drop count overflowed",
                            )
                        })?;
                    effects.mark_drop();
                    return Ok(NetworkCustodyApplication::default());
                }
                crucible::model::NetworkPolicyOverflow::DropOldest => {
                    while over_capacity {
                        let Some((victim_index, victim)) = queue
                            .reservations
                            .iter()
                            .enumerate()
                            .min_by(|(_left_index, left), (_right_index, right)| {
                                (left.enqueue_nanos, &left.bundle)
                                    .cmp(&(right.enqueue_nanos, &right.bundle))
                            })
                            .map(|(index, reservation)| (index, reservation.clone()))
                        else {
                            queue.dropped_bundles =
                                queue.dropped_bundles.checked_add(1).ok_or_else(|| {
                                    network_effect_application_error(
                                        action,
                                        "custody drop count overflowed",
                                    )
                                })?;
                            effects.mark_drop();
                            return Ok(NetworkCustodyApplication::default());
                        };
                        queue.reservations.remove(victim_index);
                        cancel_network_contact_reservations(
                            contact_services,
                            &owner,
                            &BTreeSet::from([victim.opportunity]),
                            now,
                            action,
                        )?;
                        pending_outputs.retain(|output| {
                            output.fault_continuation.cursor().queue_opportunity()
                                != Some(victim.opportunity)
                        });
                        queue.dropped_bundles =
                            queue.dropped_bundles.checked_add(1).ok_or_else(|| {
                                network_effect_application_error(
                                    action,
                                    "custody drop count overflowed",
                                )
                            })?;
                        occupied_bytes =
                            occupied_bytes.checked_sub(victim.bytes).ok_or_else(|| {
                                network_effect_application_error(
                                    action,
                                    "custody eviction occupancy underflowed",
                                )
                            })?;
                        over_capacity = occupied_bytes
                            .checked_add(payload_bytes)
                            .is_none_or(|bytes| bytes > capacity_bytes)
                            || u64::try_from(queue.reservations.len())
                                .ok()
                                .and_then(|count| count.checked_add(1))
                                .is_none_or(|count| count > capacity_bundles);
                    }
                }
                crucible::model::NetworkPolicyOverflow::TypedError => {
                    let response = typed_error.as_ref().ok_or_else(|| {
                        network_effect_application_error(
                            action,
                            "typed custody overflow omitted its response artifact",
                        )
                    })?;
                    request_typed_response(typed_response, response, action)?;
                    queue.dropped_bundles =
                        queue.dropped_bundles.checked_add(1).ok_or_else(|| {
                            network_effect_application_error(
                                action,
                                "custody drop count overflowed",
                            )
                        })?;
                    effects.mark_drop();
                    return Ok(NetworkCustodyApplication::default());
                }
                crucible::model::NetworkPolicyOverflow::Timeout => {
                    let timeout = timeout_nanos.ok_or_else(|| {
                        network_effect_application_error(
                            action,
                            "custody timeout duration disappeared",
                        )
                    })?;
                    let deadline = now
                        .checked_add(timeout.get())
                        .ok_or_else(|| {
                            network_effect_application_error(action, "custody timeout overflowed")
                        })?
                        .min(expiry_nanos);
                    queue.overflow_timeouts.push(NetworkCustodyTimeout {
                        bundle,
                        opportunity: opportunity.id(),
                        enqueue_nanos: now,
                        expiry_nanos,
                        deadline_nanos: deadline,
                    });
                    queue.overflow_timeouts.sort_by(|left, right| {
                        (left.deadline_nanos, &left.bundle)
                            .cmp(&(right.deadline_nanos, &right.bundle))
                    });
                    return Ok(NetworkCustodyApplication {
                        defer_until: Some(deadline),
                        repeat_phase_on_resume: true,
                    });
                }
            }
        }
        queue.admitted_bundles = queue.admitted_bundles.checked_add(1).ok_or_else(|| {
            network_effect_application_error(action, "custody admission count overflowed")
        })?;
    }
    let mut reservation = reserve_network_contact_route(
        state,
        topology,
        route_contact_plan,
        intervals,
        &bundle.producer,
        &bundle.destination,
        now,
        expiry_nanos,
        payload_bytes,
        max_visited_hops,
        &owner,
        opportunity.id(),
        was_existing,
        action,
    )?;
    if !was_existing
        && reservation
            .as_ref()
            .is_some_and(|reservation| reservation.first_start_nanos <= now)
    {
        reservation = reserve_network_contact_route(
            state,
            topology,
            route_contact_plan,
            intervals,
            &bundle.producer,
            &bundle.destination,
            now,
            expiry_nanos,
            payload_bytes,
            max_visited_hops,
            &owner,
            opportunity.id(),
            true,
            action,
        )?;
    }
    let (release_nanos, contact_path, contact_path_committed) =
        if let Some(reservation) = reservation {
            let committed = was_existing || reservation.first_start_nanos <= now;
            if committed {
                for identity in reservation.identities {
                    effects
                        .mark_contact_service_accounted(identity)
                        .map_err(|error| {
                            network_effect_application_error(action, &error.to_string())
                        })?;
                }
            }
            (
                if committed {
                    reservation.finish_nanos
                } else {
                    reservation.first_start_nanos
                },
                reservation.contacts,
                committed,
            )
        } else {
            let queue = state.custody_queues.get_mut(&owner).ok_or_else(|| {
                network_effect_application_error(action, "custody queue disappeared")
            })?;
            if contact_graph_has_path(
                intervals,
                &bundle.producer,
                &bundle.destination,
                max_visited_hops,
            ) {
                queue.missed_contact_bundles =
                    queue.missed_contact_bundles.checked_add(1).ok_or_else(|| {
                        network_effect_application_error(action, "missed-contact count overflowed")
                    })?;
            } else {
                queue.stale_plan_bundles =
                    queue.stale_plan_bundles.checked_add(1).ok_or_else(|| {
                        network_effect_application_error(action, "stale-plan count overflowed")
                    })?;
            }
            (expiry_nanos, Vec::new(), false)
        };
    let queue = state
        .custody_queues
        .get_mut(&owner)
        .ok_or_else(|| network_effect_application_error(action, "custody queue disappeared"))?;
    queue.reservations.push(NetworkCustodyReservation {
        bundle,
        opportunity: opportunity.id(),
        enqueue_nanos,
        expiry_nanos,
        release_nanos,
        bytes: payload_bytes,
        contact_path,
        contact_path_committed,
    });
    queue.reservations.sort_by(|left, right| {
        (
            left.bundle.priority.rank(),
            left.enqueue_nanos,
            &left.bundle,
        )
            .cmp(&(
                right.bundle.priority.rank(),
                right.enqueue_nanos,
                &right.bundle,
            ))
    });
    Ok(NetworkCustodyApplication {
        defer_until: Some(release_nanos),
        repeat_phase_on_resume: true,
    })
}

pub(in super::super) fn apply_network_frame_action(
    payload: &mut Vec<u8>,
    effects: &mut crucible::ResolvedNetworkFrameEffects,
    action: &ResolvedBindingAction,
    opportunity: &FaultOpportunity,
    scenario_seed: ContentHash,
    topology: &crucible::model::WorldFaultTopology,
    state: &mut NetworkEffectRuntimeState,
) -> Result<(), SchedulerError> {
    let EffectSpecification::Network(specification) = action.effect.specification() else {
        return Err(network_effect_application_error(
            action,
            "non-network effect reached the network adapter",
        ));
    };
    let map_effect_error = |error: crucible::ResolvedNetworkFrameEffectsError| {
        network_effect_application_error(action, &error.to_string())
    };
    match specification {
        NetworkEffectSpecification::Availability { .. } => {}
        NetworkEffectSpecification::ProfileDelta {
            latency_nanos,
            rate_cap_bps,
            loss_hazard,
            corruption_hazard,
            technology_metrics,
        } => {
            if let Some(latency_nanos) = latency_nanos {
                effects
                    .add_latency_delta(*latency_nanos)
                    .map_err(map_effect_error)?;
            }
            if let Some(rate_cap_bps) = rate_cap_bps {
                effects
                    .constrain_rate(rate_cap_bps.get())
                    .map_err(map_effect_error)?;
            }
            let input = if loss_hazard.is_some()
                || corruption_hazard.is_some()
                || technology_metrics.is_some()
            {
                Some(mapped_network_integer(action)?)
            } else {
                None
            };
            for (reference, axis) in [
                (loss_hazard.as_ref(), "profile-loss"),
                (corruption_hazard.as_ref(), "profile-corruption"),
            ] {
                if let Some(reference) = reference {
                    let probability = network_policy_lookup(
                        topology,
                        reference,
                        input.ok_or_else(|| {
                            network_effect_application_error(
                                action,
                                "profile lookup omitted its mapped input",
                            )
                        })?,
                    )?;
                    let probability = u32::try_from(probability)
                        .ok()
                        .and_then(|value| crucible::model::ProbabilityMillionths::new(value).ok())
                        .ok_or_else(|| {
                            network_effect_application_error(
                                action,
                                "profile hazard lookup did not return probability millionths",
                            )
                        })?;
                    if probability_fires(
                        probability,
                        network_effect_draw(scenario_seed, opportunity, action, axis, 0),
                    ) {
                        effects.mark_drop();
                    }
                }
            }
            if let Some(reference) = technology_metrics {
                let latency = network_policy_lookup(
                    topology,
                    reference,
                    input.ok_or_else(|| {
                        network_effect_application_error(
                            action,
                            "technology metric lookup omitted its mapped input",
                        )
                    })?,
                )?;
                effects
                    .add_latency_delta(latency)
                    .map_err(map_effect_error)?;
            }
        }
        NetworkEffectSpecification::PropagationDelay {
            delay_nanos: Some(delay_nanos),
            distance_velocity_lookup: None,
        }
        | NetworkEffectSpecification::AccessDelay { delay_nanos, .. } => effects
            .add_delay(delay_nanos.get())
            .map_err(map_effect_error)?,
        NetworkEffectSpecification::PropagationDelay {
            delay_nanos: None,
            distance_velocity_lookup: Some(reference),
        } => {
            let delay =
                network_policy_lookup(topology, reference, mapped_network_integer(action)?)?;
            let delay = u64::try_from(delay).map_err(|_error| {
                network_effect_application_error(
                    action,
                    "propagation lookup returned a negative delay",
                )
            })?;
            effects.add_delay(delay).map_err(map_effect_error)?;
        }
        NetworkEffectSpecification::Jitter {
            maximum_nanos,
            distribution: crucible::model::NetworkDistribution::Uniform,
            distribution_lookup: None,
        } => {
            let draw = network_effect_draw(scenario_seed, opportunity, action, "jitter", 0);
            effects
                .add_delay(uniform_inclusive(draw, maximum_nanos.get()))
                .map_err(map_effect_error)?;
        }
        NetworkEffectSpecification::Jitter {
            maximum_nanos,
            distribution:
                crucible::model::NetworkDistribution::NormalLookup
                | crucible::model::NetworkDistribution::ExponentialLookup,
            distribution_lookup: Some(reference),
        } => {
            let draw = network_effect_draw(scenario_seed, opportunity, action, "jitter", 0);
            let quantile = i64::from(u32::try_from(draw % 1_000_000).map_err(|_error| {
                network_effect_application_error(action, "jitter quantile conversion failed")
            })?);
            let sampled = network_policy_lookup(topology, reference, quantile)?;
            let sampled = u64::try_from(sampled).map_err(|_error| {
                network_effect_application_error(action, "jitter lookup returned a negative delay")
            })?;
            effects
                .add_delay(sampled.min(maximum_nanos.get()))
                .map_err(map_effect_error)?;
        }
        NetworkEffectSpecification::FrameLoss {
            probability,
            outcome,
        } => {
            let drop = match (probability, outcome) {
                (Some(probability), None) => probability_fires(
                    *probability,
                    network_effect_draw(scenario_seed, opportunity, action, "frame-loss", 0),
                ),
                (None, Some(crucible::model::NetworkLossDecision::Drop)) => true,
                (None, Some(crucible::model::NetworkLossDecision::Preserve)) => false,
                _ => {
                    return Err(network_effect_application_error(
                        action,
                        "frame-loss alternatives are not canonical",
                    ));
                }
            };
            if drop {
                effects.mark_drop();
            }
        }
        NetworkEffectSpecification::Duplicate {
            probability,
            gap_nanos,
            copies,
        } => {
            if probability_fires(
                *probability,
                network_effect_draw(scenario_seed, opportunity, action, "duplicate", 0),
            ) {
                for copy in 1..=copies.get() {
                    let gap = gap_nanos.checked_mul(u64::from(copy)).ok_or_else(|| {
                        network_effect_application_error(action, "duplicate gap overflowed")
                    })?;
                    effects.add_duplicate_gap(gap).map_err(map_effect_error)?;
                }
            }
        }
        NetworkEffectSpecification::Reorder {
            window_nanos,
            selection,
        } => {
            let delay = match selection {
                crucible::model::NetworkSelection::Oldest => 0,
                crucible::model::NetworkSelection::Newest => window_nanos.get(),
                crucible::model::NetworkSelection::KeyedUniform
                | crucible::model::NetworkSelection::CanonicalOrder => uniform_inclusive(
                    network_effect_draw(scenario_seed, opportunity, action, "reorder", 0),
                    window_nanos.get(),
                ),
            };
            effects.add_delay(delay).map_err(map_effect_error)?;
        }
        NetworkEffectSpecification::PayloadTransform { mutation } => match mutation {
            crucible::model::NetworkPayloadMutation::BitFlip {
                offset_bytes,
                length_bytes,
                mask,
            } => {
                let start = usize::try_from(*offset_bytes).map_err(|_error| {
                    network_effect_application_error(action, "payload offset exceeds host width")
                })?;
                let length = usize::try_from(length_bytes.get()).map_err(|_error| {
                    network_effect_application_error(action, "payload length exceeds host width")
                })?;
                let end = start.checked_add(length).ok_or_else(|| {
                    network_effect_application_error(action, "payload byte range overflowed")
                })?;
                let selected = payload.get_mut(start..end).ok_or_else(|| {
                    network_effect_application_error(
                        action,
                        "payload transform selected bytes outside the frame",
                    )
                })?;
                for byte in selected {
                    *byte ^= *mask;
                }
            }
            crucible::model::NetworkPayloadMutation::Truncate { length_bytes } => {
                let length = usize::try_from(*length_bytes).map_err(|_error| {
                    network_effect_application_error(
                        action,
                        "payload truncation length exceeds host width",
                    )
                })?;
                payload.truncate(length);
            }
            crucible::model::NetworkPayloadMutation::FieldMutation { field, replacement } => {
                apply_network_field_mutation(payload, topology, field, replacement, action)?;
            }
            crucible::model::NetworkPayloadMutation::UndetectedCorruption { transform } => {
                let bytes = network_byte_template(topology, transform, action)?;
                if bytes.is_empty() {
                    return Err(network_effect_application_error(
                        action,
                        "undetected corruption template is empty",
                    ));
                }
                for (index, byte) in payload.iter_mut().enumerate() {
                    *byte ^= bytes[index % bytes.len()];
                }
            }
        },
        NetworkEffectSpecification::DetectedFrameError {
            receiver_action: crucible::model::DetectedFrameErrorAction::Corrected,
            ..
        } => {}
        NetworkEffectSpecification::DetectedFrameError {
            receiver_action: crucible::model::DetectedFrameErrorAction::Drop,
            ..
        } => effects.mark_drop(),
        NetworkEffectSpecification::DetectedFrameError {
            receiver_action: crucible::model::DetectedFrameErrorAction::Retry,
            retry_delay_nanos: Some(retry_delay_nanos),
            retry_attempts: Some(retry_attempts),
            retry_succeeds: Some(retry_succeeds),
            ..
        } => {
            let retry_delay = retry_delay_nanos
                .get()
                .checked_mul(u64::from(retry_attempts.get()))
                .ok_or_else(|| {
                    network_effect_application_error(action, "detected-error retries overflowed")
                })?;
            effects.add_delay(retry_delay).map_err(map_effect_error)?;
            if !retry_succeeds {
                effects.mark_drop();
            }
        }
        NetworkEffectSpecification::DetectedFrameError {
            receiver_action: crucible::model::DetectedFrameErrorAction::LinkReset,
            reset_nanos: Some(reset_nanos),
            ..
        } => {
            state.boundary.activate_timed_outage(
                action,
                opportunity.coordinate().virtual_nanos,
                reset_nanos.get(),
            )?;
            effects.mark_drop();
        }
        NetworkEffectSpecification::DetectedFrameError { .. } => {
            return Err(network_effect_application_error(
                action,
                "detected-frame-error parameters contradicted admission",
            ));
        }
        NetworkEffectSpecification::Mtu { .. } => {
            return Err(network_effect_application_error(
                action,
                "MTU effects require the composed frame executor",
            ));
        }
        NetworkEffectSpecification::RecipientSubset {
            membership_version,
            drop_members,
            selection,
            retain_count,
        } => {
            apply_network_recipient_subset(
                effects,
                action,
                opportunity,
                scenario_seed,
                topology,
                membership_version,
                drop_members.as_ref(),
                selection.as_ref(),
                retain_count.as_ref(),
            )?;
        }
        NetworkEffectSpecification::FirewallDisposition {
            action: crucible::model::NetworkFirewallAction::Accept,
            ..
        } => {}
        NetworkEffectSpecification::FirewallDisposition {
            action: crucible::model::NetworkFirewallAction::Drop,
            ..
        }
        | NetworkEffectSpecification::ForwardingMutation {
            mutation: crucible::model::NetworkForwardingMutationKind::Blackhole,
            ..
        } => effects.mark_drop(),
        NetworkEffectSpecification::Contact {
            intervals,
            range_delay_lookup,
            ..
        } => {
            let contact_plan = intervals;
            let declaration = topology
                .network_policy_artifact(contact_plan)
                .ok_or_else(|| {
                    network_effect_application_error(action, "contact plan disappeared")
                })?;
            let crucible::model::NetworkPolicyArtifactKind::ContactPlan {
                intervals: contact_intervals,
            } = &declaration.artifact
            else {
                return Err(network_effect_application_error(
                    action,
                    "contact plan changed type after admission",
                ));
            };
            let now = opportunity.coordinate().virtual_nanos;
            let OpportunityPayload::NetworkFrame {
                producer,
                destination,
                ..
            } = opportunity.payload()
            else {
                return Err(network_effect_application_error(
                    action,
                    "contact effect received a non-frame opportunity",
                ));
            };
            if contact_intervals.iter().any(|interval| {
                effects.contact_service_is_accounted(&network_contact_service_identity(
                    &NetworkContactServiceKey {
                        plan: contact_plan.clone(),
                        contact: interval.contact.clone(),
                        service_resource: interval.service_resource.clone(),
                        source: interval.source.clone(),
                        destination: interval.destination.clone(),
                        start_nanos: interval.start_nanos,
                        end_nanos: interval.end_nanos,
                    },
                ))
            }) {
                return Ok(());
            }
            let interval = contact_intervals.iter().find(|interval| {
                let open = interval.start_nanos.checked_add(interval.acquisition_nanos);
                let teardown = interval.end_nanos.checked_sub(interval.teardown_nanos);
                &interval.source == producer
                    && &interval.destination == destination
                    && open.is_some_and(|open| {
                        teardown.is_some_and(|teardown| open <= now && now < teardown)
                    })
            });
            let Some(interval) = interval else {
                effects.mark_drop();
                return Ok(());
            };
            let range = u64::try_from(mapped_network_service_input(
                action,
                "range",
                &crucible::model::SignalShape {
                    value_type: crucible::model::SignalValueType::U64,
                    unit: crucible::model::SignalUnit::Millimetres,
                    scale_decimal_exponent: 0,
                },
            )?)
            .map_err(|_error| {
                network_effect_application_error(action, "contact range is negative")
            })?;
            if range < interval.minimum_range_mm || range > interval.maximum_range_mm {
                return Err(network_effect_application_error(
                    action,
                    "contact range lies outside the admitted interval bounds",
                ));
            }
            let delay = network_policy_lookup(
                topology,
                range_delay_lookup,
                i64::try_from(range).map_err(|_error| {
                    network_effect_application_error(action, "contact range exceeds i64")
                })?,
            )?;
            effects
                .add_delay(u64::try_from(delay).map_err(|_error| {
                    network_effect_application_error(action, "contact delay is negative")
                })?)
                .map_err(map_effect_error)?;
            let contact_key = NetworkContactServiceKey {
                plan: contact_plan.clone(),
                contact: interval.contact.clone(),
                service_resource: interval.service_resource.clone(),
                source: producer.clone(),
                destination: destination.clone(),
                start_nanos: interval.start_nanos,
                end_nanos: interval.end_nanos,
            };
            let contact_identity = network_contact_service_identity(&contact_key);
            debug_assert!(!effects.contact_service_is_accounted(&contact_identity));
            let payload_bytes = u64::try_from(payload.len()).map_err(|_error| {
                network_effect_application_error(action, "contact frame size exceeds u64")
            })?;
            let Some((finish, reserved_identity)) = reserve_network_contact_service(
                state,
                topology,
                contact_plan,
                interval,
                producer,
                destination,
                now,
                payload_bytes,
                opportunity.id(),
                action,
            )?
            else {
                effects.mark_drop();
                return Ok(());
            };
            effects
                .add_delay(finish.checked_sub(now).ok_or_else(|| {
                    network_effect_application_error(action, "contact service regressed")
                })?)
                .map_err(map_effect_error)?;
            effects
                .mark_contact_service_accounted(reserved_identity)
                .map_err(map_effect_error)?;
        }
        NetworkEffectSpecification::RfChannel {
            transmit_power_femtowatts,
            receiver_noise_femtowatts,
            propagation_fields,
            sinr_transfer,
            ..
        } => {
            let distance = mapped_network_service_u64(
                action,
                "distance",
                &crucible::model::SignalShape {
                    value_type: crucible::model::SignalValueType::U64,
                    unit: crucible::model::SignalUnit::Millimetres,
                    scale_decimal_exponent: 0,
                },
            )?;
            let orientation = mapped_network_service_input(
                action,
                "orientation",
                &crucible::model::SignalShape {
                    value_type: crucible::model::SignalValueType::I64,
                    unit: crucible::model::SignalUnit::Millidegrees,
                    scale_decimal_exponent: 0,
                },
            )?;
            let propagation = topology
                .network_policy_artifact(propagation_fields)
                .ok_or_else(|| {
                    network_effect_application_error(action, "RF propagation policy disappeared")
                })?;
            let crucible::model::NetworkPolicyArtifactKind::RfPropagation(propagation) =
                &propagation.artifact
            else {
                return Err(network_effect_application_error(
                    action,
                    "RF propagation policy changed type after admission",
                ));
            };
            let path_gain = lookup_network_integer_table(
                &propagation.path_gain_ratio,
                i64::try_from(distance).map_err(|_error| {
                    network_effect_application_error(action, "RF distance exceeds lookup width")
                })?,
                "rf.path_gain_ratio",
            )?;
            let antenna_gain = lookup_network_integer_table(
                &propagation.antenna_gain_ratio,
                orientation,
                "rf.antenna_gain_ratio",
            )?;
            let fading = mapped_network_service_u64(
                action,
                "fading",
                &crucible::model::SignalShape {
                    value_type: crucible::model::SignalValueType::U64,
                    unit: crucible::model::SignalUnit::PartsPerMillion,
                    scale_decimal_exponent: 0,
                },
            )?;
            let path_gain = u64::try_from(path_gain).map_err(|_error| {
                network_effect_application_error(action, "RF path gain ratio is negative")
            })?;
            let antenna_gain = u64::try_from(antenna_gain).map_err(|_error| {
                network_effect_application_error(action, "RF antenna gain ratio is negative")
            })?;
            let signal = multiply_ratio_millionths(*transmit_power_femtowatts, path_gain, action)?;
            let signal = multiply_ratio_millionths(signal, antenna_gain, action)?;
            let signal = multiply_ratio_millionths(signal, fading, action)?;
            let interference = mapped_network_service_u64(
                action,
                "interference",
                &crucible::model::SignalShape {
                    value_type: crucible::model::SignalValueType::U64,
                    unit: crucible::model::SignalUnit::Femtowatts,
                    scale_decimal_exponent: 0,
                },
            )?;
            let denominator = interference
                .checked_add(*receiver_noise_femtowatts)
                .ok_or_else(|| {
                    network_effect_application_error(action, "RF noise power overflowed")
                })?;
            if denominator == 0 {
                return Err(network_effect_application_error(
                    action,
                    "RF interference plus receiver noise must be positive",
                ));
            }
            let sinr = divide_ties_to_even(
                u128::from(signal).checked_mul(1_000_000).ok_or_else(|| {
                    network_effect_application_error(action, "RF SINR numerator overflowed")
                })?,
                u128::from(denominator),
            );
            let sinr = i64::try_from(sinr).map_err(|_error| {
                network_effect_application_error(action, "RF SINR exceeds transfer-table width")
            })?;
            let transfer = topology
                .network_policy_artifact(sinr_transfer)
                .ok_or_else(|| {
                    network_effect_application_error(action, "RF transfer policy disappeared")
                })?;
            let crucible::model::NetworkPolicyArtifactKind::RfTransfer(transfer) =
                &transfer.artifact
            else {
                return Err(network_effect_application_error(
                    action,
                    "RF transfer policy changed type after admission",
                ));
            };
            let profile_index = transfer
                .profiles
                .partition_point(|profile| profile.minimum_sinr <= sinr)
                .checked_sub(1)
                .ok_or_else(|| {
                    network_effect_application_error(action, "RF SINR precedes every profile")
                })?;
            let profile = &transfer.profiles[profile_index];
            effects
                .constrain_rate(profile.rate_bps.get())
                .map_err(map_effect_error)?;
            for attempt in 0..=profile.maximum_retries {
                let ordinal = u64::from(attempt);
                let lost = probability_fires(
                    profile.loss,
                    network_effect_draw(scenario_seed, opportunity, action, "rf-loss", ordinal),
                );
                if lost {
                    if attempt == profile.maximum_retries {
                        effects.mark_drop();
                        break;
                    }
                    effects
                        .add_delay(profile.retry_delay_nanos)
                        .map_err(map_effect_error)?;
                    continue;
                }
                let corrupted = probability_fires(
                    profile.corruption,
                    network_effect_draw(
                        scenario_seed,
                        opportunity,
                        action,
                        "rf-corruption",
                        ordinal,
                    ),
                );
                if !corrupted {
                    break;
                }
                match &profile.corruption_action {
                    crucible::model::NetworkPolicyRfCorruption::Corrected => break,
                    crucible::model::NetworkPolicyRfCorruption::Undetected { transform } => {
                        let bytes = network_byte_template(topology, transform, action)?;
                        if bytes.is_empty() {
                            return Err(network_effect_application_error(
                                action,
                                "RF undetected-corruption template is empty",
                            ));
                        }
                        for (index, byte) in payload.iter_mut().enumerate() {
                            *byte ^= bytes[index % bytes.len()];
                        }
                        break;
                    }
                    crucible::model::NetworkPolicyRfCorruption::Detected => {
                        if attempt == profile.maximum_retries {
                            effects.mark_drop();
                            break;
                        }
                        effects
                            .add_delay(profile.retry_delay_nanos)
                            .map_err(map_effect_error)?;
                    }
                }
            }
        }
        NetworkEffectSpecification::SharedMedium { .. } => {
            return Err(network_effect_application_error(
                action,
                "shared-medium effect bypassed its joint state executor",
            ));
        }
        NetworkEffectSpecification::Flap { .. }
        | NetworkEffectSpecification::NegotiatedMode { .. }
        | NetworkEffectSpecification::PropagationDelay { .. }
        | NetworkEffectSpecification::Jitter { .. }
        | NetworkEffectSpecification::ServiceCurve { .. }
        | NetworkEffectSpecification::TokenBucket { .. }
        | NetworkEffectSpecification::QueuePolicy { .. }
        | NetworkEffectSpecification::BurstErrorState { .. }
        | NetworkEffectSpecification::PauseBackpressure { .. }
        | NetworkEffectSpecification::ForwarderLifecycle { .. }
        | NetworkEffectSpecification::ForwardingMutation { .. }
        | NetworkEffectSpecification::RouteTransition { .. }
        | NetworkEffectSpecification::ControlPlaneService { .. }
        | NetworkEffectSpecification::FirewallDisposition { .. }
        | NetworkEffectSpecification::ConnectionState { .. }
        | NetworkEffectSpecification::Association { .. }
        | NetworkEffectSpecification::ControlResultTransform { .. }
        | NetworkEffectSpecification::CustodyQueue { .. } => {
            return Err(network_effect_application_error(
                action,
                "effect requires network phase state that is not yet present",
            ));
        }
    }
    Ok(())
}

pub(super) trait NetworkEffectContext {
    fn binding(&self) -> &FaultObjectId;
    fn effect_kind(&self) -> crucible::model::EffectKind;
}

impl NetworkEffectContext for ResolvedBindingAction {
    fn binding(&self) -> &FaultObjectId {
        &self.binding
    }

    fn effect_kind(&self) -> crucible::model::EffectKind {
        self.effect.kind()
    }
}

impl NetworkEffectContext for NetworkEffectStateKey {
    fn binding(&self) -> &FaultObjectId {
        &self.binding
    }

    fn effect_kind(&self) -> crucible::model::EffectKind {
        self.effect
    }
}

pub(in super::super) fn network_effect_application_error(
    action: &impl NetworkEffectContext,
    reason: &str,
) -> SchedulerError {
    SchedulerError::BoundaryViolation {
        message: format!(
            "apply network effect `{}` from binding `{}`: {reason}",
            action.effect_kind().as_str(),
            action.binding()
        ),
    }
}

pub(in super::super) fn network_effect_draw(
    scenario_seed: ContentHash,
    opportunity: &FaultOpportunity,
    action: &ResolvedBindingAction,
    axis: &str,
    ordinal: u64,
) -> u64 {
    let mut material = Vec::new();
    material.extend_from_slice(&scenario_seed.bytes);
    material.extend_from_slice(&opportunity.id().bytes);
    material.extend_from_slice(&action.id().bytes);
    material.extend_from_slice(axis.as_bytes());
    material.extend_from_slice(&ordinal.to_be_bytes());
    let digest = ContentHash::from_bytes(&material);
    let mut draw = [0_u8; 8];
    draw.copy_from_slice(&digest.bytes[..8]);
    u64::from_be_bytes(draw)
}

pub(in super::super) fn probability_fires(
    probability: crucible::model::ProbabilityMillionths,
    draw: u64,
) -> bool {
    draw % 1_000_000 < u64::from(probability.get())
}

pub(in super::super) fn uniform_inclusive(draw: u64, maximum: u64) -> u64 {
    let range = u128::from(maximum) + 1;
    ((u128::from(draw) * range) >> 64) as u64
}

#[allow(clippy::too_many_arguments)]
pub(in super::super) fn apply_network_recipient_subset(
    effects: &mut crucible::ResolvedNetworkFrameEffects,
    action: &ResolvedBindingAction,
    opportunity: &FaultOpportunity,
    scenario_seed: ContentHash,
    topology: &crucible::model::WorldFaultTopology,
    membership_version: &FaultObjectId,
    drop_members: Option<&crucible::model::ObjectIdSet>,
    selection: Option<&crucible::model::NetworkSelection>,
    retain_count: Option<&crucible::model::BoundedCount>,
) -> Result<(), SchedulerError> {
    let declaration = topology
        .network_policy_artifact(membership_version)
        .ok_or_else(|| {
            network_effect_application_error(action, "recipient membership disappeared")
        })?;
    let crucible::model::NetworkPolicyArtifactKind::RecipientMembership { members } =
        &declaration.artifact
    else {
        return Err(network_effect_application_error(
            action,
            "recipient membership changed type after admission",
        ));
    };
    let OpportunityPayload::NetworkFrame {
        producer,
        destination,
        producer_sequence,
        ..
    } = opportunity.payload()
    else {
        return Err(network_effect_application_error(
            action,
            "recipient subset received a non-frame opportunity",
        ));
    };
    if members
        .binary_search_by(|candidate| candidate.member.cmp(destination))
        .is_err()
    {
        return Err(network_effect_application_error(
            action,
            "frame destination is absent from the admitted membership version",
        ));
    }
    if let Some(drop_members) = drop_members {
        if drop_members.as_slice().binary_search(destination).is_ok() {
            effects.mark_drop();
        }
        return Ok(());
    }
    let selection = selection
        .ok_or_else(|| network_effect_application_error(action, "recipient selection is absent"))?;
    let retain = retain_count
        .and_then(|count| usize::try_from(count.get()).ok())
        .ok_or_else(|| {
            network_effect_application_error(action, "recipient retain count exceeds host width")
        })?;
    let mut selected = members.iter().collect::<Vec<_>>();
    match selection {
        crucible::model::NetworkSelection::Oldest => selected.sort_by(|left, right| {
            left.joined_sequence
                .cmp(&right.joined_sequence)
                .then_with(|| left.member.cmp(&right.member))
        }),
        crucible::model::NetworkSelection::Newest => selected.sort_by(|left, right| {
            right
                .joined_sequence
                .cmp(&left.joined_sequence)
                .then_with(|| left.member.cmp(&right.member))
        }),
        crucible::model::NetworkSelection::CanonicalOrder => {}
        crucible::model::NetworkSelection::KeyedUniform => {
            selected.sort_by(|left, right| {
                network_recipient_rank(
                    scenario_seed,
                    action,
                    membership_version,
                    producer,
                    *producer_sequence,
                    &left.member,
                )
                .bytes
                .cmp(
                    &network_recipient_rank(
                        scenario_seed,
                        action,
                        membership_version,
                        producer,
                        *producer_sequence,
                        &right.member,
                    )
                    .bytes,
                )
                .then_with(|| left.member.cmp(&right.member))
            });
        }
    }
    if !selected
        .iter()
        .take(retain)
        .any(|candidate| &candidate.member == destination)
    {
        effects.mark_drop();
    }
    Ok(())
}

pub(in super::super) fn network_recipient_rank(
    scenario_seed: ContentHash,
    action: &ResolvedBindingAction,
    membership_version: &FaultObjectId,
    producer: &FaultObjectId,
    producer_sequence: u64,
    recipient: &FaultObjectId,
) -> ContentHash {
    let mut material = b"crucible.network-recipient-rank.v1\0".to_vec();
    material.extend_from_slice(&scenario_seed.bytes);
    material.extend_from_slice(action.binding.as_str().as_bytes());
    material.push(0);
    material.extend_from_slice(membership_version.as_str().as_bytes());
    material.push(0);
    material.extend_from_slice(producer.as_str().as_bytes());
    material.push(0);
    material.extend_from_slice(&producer_sequence.to_be_bytes());
    material.extend_from_slice(recipient.as_str().as_bytes());
    ContentHash::from_bytes(&material)
}

pub(in super::super) fn mapped_network_integer(
    action: &ResolvedBindingAction,
) -> Result<i64, SchedulerError> {
    mapped_network_integers(action)?
        .into_iter()
        .next()
        .ok_or_else(|| network_effect_application_error(action, "network lookup has no input"))
}

pub(in super::super) fn mapped_network_service_input(
    action: &ResolvedBindingAction,
    role: &str,
    expected: &crucible::model::SignalShape,
) -> Result<i64, SchedulerError> {
    let crucible::model::ResolvedMappingOutput::ServiceProfile {
        input_contracts,
        inputs,
        ..
    } = action.mapping_output.as_ref()
    else {
        return Err(network_effect_application_error(
            action,
            "network service effect requires a service-profile mapping",
        ));
    };
    if input_contracts.len() != inputs.len() {
        return Err(network_effect_application_error(
            action,
            "network service input shapes and values differ in length",
        ));
    }
    let mut matches = input_contracts
        .iter()
        .zip(inputs)
        .filter(|(contract, _value)| contract.role.as_str() == role && &contract.shape == expected);
    let (_contract, value) = matches.next().ok_or_else(|| {
        network_effect_application_error(action, "network service omitted a physical input")
    })?;
    if matches.next().is_some() {
        return Err(network_effect_application_error(
            action,
            "network service repeated a physical input shape",
        ));
    }
    mapped_network_scalar(action, value)
}

pub(in super::super) fn mapped_network_service_u64(
    action: &ResolvedBindingAction,
    role: &str,
    expected: &crucible::model::SignalShape,
) -> Result<u64, SchedulerError> {
    let crucible::model::ResolvedMappingOutput::ServiceProfile {
        input_contracts,
        inputs,
        ..
    } = action.mapping_output.as_ref()
    else {
        return Err(network_effect_application_error(
            action,
            "network service effect requires a service-profile mapping",
        ));
    };
    if input_contracts.len() != inputs.len() {
        return Err(network_effect_application_error(
            action,
            "network service input shapes and values differ in length",
        ));
    }
    let mut matches = input_contracts
        .iter()
        .zip(inputs)
        .filter(|(contract, _value)| contract.role.as_str() == role && &contract.shape == expected);
    let (_contract, value) = matches.next().ok_or_else(|| {
        network_effect_application_error(action, "network service omitted a physical input")
    })?;
    if matches.next().is_some() {
        return Err(network_effect_application_error(
            action,
            "network service repeated a physical input shape",
        ));
    }
    let crucible::model::SignalValue::U64(value) = value else {
        return Err(network_effect_application_error(
            action,
            "network service input is not an unsigned integer",
        ));
    };
    Ok(*value)
}

pub(in super::super) fn multiply_ratio_millionths(
    value: u64,
    ratio_millionths: u64,
    action: &ResolvedBindingAction,
) -> Result<u64, SchedulerError> {
    let product = u128::from(value)
        .checked_mul(u128::from(ratio_millionths))
        .ok_or_else(|| network_effect_application_error(action, "RF power product overflowed"))?;
    u64::try_from(divide_ties_to_even(product, 1_000_000)).map_err(|_error| {
        network_effect_application_error(action, "RF scaled power exceeds femtowatt width")
    })
}

pub(in super::super) fn divide_ties_to_even(numerator: u128, denominator: u128) -> u128 {
    let quotient = numerator / denominator;
    let remainder = numerator % denominator;
    let half = denominator / 2;
    let above_half = remainder > half;
    let exactly_half = denominator.is_multiple_of(2) && remainder == half;
    if above_half || exactly_half && quotient % 2 == 1 {
        quotient + 1
    } else {
        quotient
    }
}

pub(in super::super) fn mapped_network_integers(
    action: &ResolvedBindingAction,
) -> Result<Vec<i64>, SchedulerError> {
    let values = match action.mapping_output.as_ref() {
        crucible::model::ResolvedMappingOutput::Parameter { value, .. } => {
            std::slice::from_ref(value)
        }
        crucible::model::ResolvedMappingOutput::ServiceProfile { inputs, .. } => inputs.as_slice(),
        crucible::model::ResolvedMappingOutput::Activation { .. }
        | crucible::model::ResolvedMappingOutput::Hazard { .. }
        | crucible::model::ResolvedMappingOutput::Impulse { .. }
        | crucible::model::ResolvedMappingOutput::StateTransition { .. } => {
            return Err(network_effect_application_error(
                action,
                "network lookup requires a numeric parameter or service-profile input",
            ));
        }
    };
    if values.is_empty() {
        return Err(network_effect_application_error(
            action,
            "network lookup has no numeric input",
        ));
    }
    values
        .iter()
        .map(|value| mapped_network_scalar(action, value))
        .collect()
}

pub(in super::super) fn mapped_network_scalar(
    action: &ResolvedBindingAction,
    value: &crucible::model::SignalValue,
) -> Result<i64, SchedulerError> {
    match value {
        crucible::model::SignalValue::I64(value) => Ok(*value),
        crucible::model::SignalValue::U64(value)
        | crucible::model::SignalValue::DurationNanos(value)
        | crucible::model::SignalValue::RatePerSecond(value) => {
            i64::try_from(*value).map_err(|_error| {
                network_effect_application_error(action, "network lookup input exceeds i64")
            })
        }
        crucible::model::SignalValue::ProbabilityMillionths(value) => Ok(i64::from(*value)),
        crucible::model::SignalValue::Bool(_)
        | crucible::model::SignalValue::Ratio(_)
        | crucible::model::SignalValue::Enum { .. }
        | crucible::model::SignalValue::Event { .. }
        | crucible::model::SignalValue::Vector2(_)
        | crucible::model::SignalValue::Vector3(_)
        | crucible::model::SignalValue::Bytes(_) => Err(network_effect_application_error(
            action,
            "network lookup input is not an integer scalar",
        )),
    }
}

pub(in super::super) fn network_policy_lookup(
    topology: &crucible::model::WorldFaultTopology,
    reference: &FaultObjectId,
    input: i64,
) -> Result<i64, SchedulerError> {
    let declaration = topology.network_policy_artifact(reference).ok_or_else(|| {
        SchedulerError::BoundaryViolation {
            message: format!("network policy `{reference}` disappeared after admission"),
        }
    })?;
    let crucible::model::NetworkPolicyArtifactKind::IntegerLookup(table) = &declaration.artifact
    else {
        return Err(SchedulerError::BoundaryViolation {
            message: format!(
                "network policy `{reference}` changed from integer_lookup after admission"
            ),
        });
    };
    lookup_network_integer_table(table, input, reference.as_str())
}

pub(in super::super) fn lookup_network_integer_table(
    table: &crucible::model::NetworkPolicyIntegerTable,
    input: i64,
    context: &str,
) -> Result<i64, SchedulerError> {
    let insertion = table.points.partition_point(|point| point.input <= input);
    if insertion == 0 {
        return match table.outside {
            crucible::model::NetworkPolicyOutsideRange::Clamp => Ok(table.points[0].output),
            crucible::model::NetworkPolicyOutsideRange::TypedError => {
                Err(SchedulerError::BoundaryViolation {
                    message: format!(
                        "network policy `{context}` input {input} precedes its domain"
                    ),
                })
            }
        };
    }
    let lower = table.points[insertion - 1];
    let Some(upper) = table.points.get(insertion).copied() else {
        if input == lower.input
            || table.outside == crucible::model::NetworkPolicyOutsideRange::Clamp
        {
            return Ok(lower.output);
        }
        return Err(SchedulerError::BoundaryViolation {
            message: format!("network policy `{context}` input {input} follows its domain"),
        });
    };
    match table.interpolation {
        crucible::model::NetworkPolicyInterpolation::Step => Ok(lower.output),
        crucible::model::NetworkPolicyInterpolation::LinearTiesToEven => {
            interpolate_network_policy(lower, upper, input).ok_or_else(|| {
                SchedulerError::BoundaryViolation {
                    message: format!("network policy `{context}` interpolation overflowed"),
                }
            })
        }
    }
}

pub(in super::super) fn interpolate_network_policy(
    lower: crucible::model::NetworkPolicyIntegerPoint,
    upper: crucible::model::NetworkPolicyIntegerPoint,
    input: i64,
) -> Option<i64> {
    let width = i128::from(upper.input).checked_sub(i128::from(lower.input))?;
    let offset = i128::from(input).checked_sub(i128::from(lower.input))?;
    let delta = i128::from(upper.output).checked_sub(i128::from(lower.output))?;
    let numerator = delta.checked_mul(offset)?;
    let quotient = numerator.div_euclid(width);
    let remainder = numerator.rem_euclid(width);
    let doubled = remainder.checked_mul(2)?;
    let increment = doubled > width || (doubled == width && quotient.rem_euclid(2) == 1);
    let interpolated = i128::from(lower.output)
        .checked_add(quotient)?
        .checked_add(i128::from(increment))?;
    i64::try_from(interpolated).ok()
}

pub(in super::super) fn network_byte_template<'a>(
    topology: &'a crucible::model::WorldFaultTopology,
    reference: &FaultObjectId,
    action: &ResolvedBindingAction,
) -> Result<&'a [u8], SchedulerError> {
    let declaration = topology.network_policy_artifact(reference).ok_or_else(|| {
        network_effect_application_error(action, "network byte template disappeared")
    })?;
    let crucible::model::NetworkPolicyArtifactKind::ByteTemplate { bytes } = &declaration.artifact
    else {
        return Err(network_effect_application_error(
            action,
            "network byte template changed type after admission",
        ));
    };
    Ok(bytes)
}

pub(in super::super) fn apply_network_field_mutation(
    payload: &mut [u8],
    topology: &crucible::model::WorldFaultTopology,
    selector: &FaultObjectId,
    replacement: &FaultObjectId,
    action: &ResolvedBindingAction,
) -> Result<(), SchedulerError> {
    let declaration = topology.network_policy_artifact(selector).ok_or_else(|| {
        network_effect_application_error(action, "network field selector disappeared")
    })?;
    let crucible::model::NetworkPolicyArtifactKind::PacketSelector { matches } =
        &declaration.artifact
    else {
        return Err(network_effect_application_error(
            action,
            "network field selector changed type after admission",
        ));
    };
    let replacement = network_byte_template(topology, replacement, action)?;
    let mut selected = Vec::new();
    for predicate in matches {
        let start = usize::try_from(predicate.offset_bytes).map_err(|_error| {
            network_effect_application_error(action, "field selector offset exceeds host width")
        })?;
        let end = start.checked_add(predicate.value.len()).ok_or_else(|| {
            network_effect_application_error(action, "field selector range overflowed")
        })?;
        let bytes = payload.get(start..end).ok_or_else(|| {
            network_effect_application_error(action, "field selector is outside the frame")
        })?;
        if !bytes
            .iter()
            .zip(&predicate.value)
            .zip(&predicate.mask)
            .all(|((actual, expected), mask)| actual & mask == expected & mask)
        {
            return Ok(());
        }
        selected.push((start, end));
    }
    let selected_length = selected.iter().try_fold(0_usize, |total, (start, end)| {
        total.checked_add(end - start)
    });
    if selected_length != Some(replacement.len()) {
        return Err(network_effect_application_error(
            action,
            "field replacement length does not match selected bytes",
        ));
    }
    let mut cursor = 0;
    for (start, end) in selected {
        let length = end - start;
        payload[start..end].copy_from_slice(&replacement[cursor..cursor + length]);
        cursor += length;
    }
    Ok(())
}

pub(in super::super) fn network_packet_selector_matches(
    payload: &[u8],
    topology: &crucible::model::WorldFaultTopology,
    selector: &FaultObjectId,
    action: &ResolvedBindingAction,
) -> Result<bool, SchedulerError> {
    let declaration = topology.network_policy_artifact(selector).ok_or_else(|| {
        network_effect_application_error(action, "network packet selector disappeared")
    })?;
    let crucible::model::NetworkPolicyArtifactKind::PacketSelector { matches } =
        &declaration.artifact
    else {
        return Err(network_effect_application_error(
            action,
            "network packet selector changed type after admission",
        ));
    };
    for predicate in matches {
        let start = usize::try_from(predicate.offset_bytes).map_err(|_error| {
            network_effect_application_error(action, "packet selector offset exceeds host width")
        })?;
        let Some(end) = start.checked_add(predicate.value.len()) else {
            return Err(network_effect_application_error(
                action,
                "packet selector range overflowed",
            ));
        };
        let Some(bytes) = payload.get(start..end) else {
            return Ok(false);
        };
        if !bytes
            .iter()
            .zip(&predicate.value)
            .zip(&predicate.mask)
            .all(|((actual, expected), mask)| actual & mask == expected & mask)
        {
            return Ok(false);
        }
    }
    Ok(true)
}
