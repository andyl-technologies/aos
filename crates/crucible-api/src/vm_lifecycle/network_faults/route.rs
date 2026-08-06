//! Ordered per-frame execution for signal-driven network effects.
//!
//! The route executor evaluates every declared target and phase, owns resumable
//! queue continuations, and composes exact per-frame outcomes before the legacy-
//! free link delivery model receives a frame.

use super::*;

impl BackendNetworkOutputInterceptor<SingleScheduler, ProductionNodeSet>
    for ProductionFaultNetworkInterceptor
{
    fn intercept_network_outputs(
        &mut self,
        loop_impl: &mut SingleScheduler,
        _backend: &mut ProductionNodeSet,
        frontier: VirtualTime,
        pending_outputs: &mut Vec<crucible::BackendNetworkOutput>,
        outputs: &mut Vec<crucible::BackendNetworkOutput>,
    ) -> Result<Vec<SchedulerEventLogAppend>, SchedulerError> {
        let cursor_before = (self.coordinate, self.coordinate_sequence);
        let mut staged_scheduler = loop_impl.clone();
        let mut staged_pending = pending_outputs.clone();
        let source_outputs = outputs.clone();
        let mut routed = Vec::new();
        let mut observations = Vec::new();
        let mut transition_records = Vec::new();
        let mut next_wakeup_nanos = None;
        let mut runtime_committed = false;
        let mut staged_effect_state = self.effect_state.clone();
        let staged = (|| {
            for output in source_outputs {
                'route: for route in staged_scheduler.resolve_backend_network_routes(&output)? {
                    let mut output = output.clone();
                    output.route = Some(route.clone());
                    let mut stages = self
                    .topology
                    .network_route_fault_targets(
                        &output.source.name,
                        &route.destination.name,
                        frontier.ticks,
                    )
                    .map_err(|error| SchedulerError::BoundaryViolation {
                        message: format!(
                            "network fault route `{}` {:?} is not represented by the admitted World fault topology: {error}",
                            route.link.name, route.direction
                        ),
                    })?;
                    let current_path = stages.iter().find_map(|stage| match &stage.target {
                        crucible::model::ResolvedFaultTarget::NetworkPath {
                            path_version, ..
                        } => Some(path_version),
                        _ => None,
                    });
                    let path_override = output
                        .fault_continuation
                        .cursor()
                        .route_path_version()
                        .or_else(|| {
                            current_path.and_then(|path| {
                                staged_effect_state
                                    .boundary
                                    .route_path_override(path, frontier.ticks)
                            })
                        });
                    if let Some(path_override) = path_override {
                        stages = self
                            .topology
                            .network_route_fault_targets_with_path(
                                &output.source.name,
                                &route.destination.name,
                                frontier.ticks,
                                Some(path_override),
                            )
                            .map_err(|error| SchedulerError::BoundaryViolation {
                                message: format!(
                                    "network route transition selected invalid path `{path_override}`: {error}"
                                ),
                            })?;
                    }
                    if output
                        .fault_continuation
                        .cursor()
                        .route_path_version()
                        .is_none()
                    {
                        if let Some(path) = stages.iter().find_map(|stage| match &stage.target {
                            crucible::model::ResolvedFaultTarget::NetworkPath {
                                path_version,
                                ..
                            } => Some(path_version.clone()),
                            _ => None,
                        }) {
                            output.fault_continuation.cursor_mut().lock_route_path(path);
                        }
                    }
                    let producer = FaultObjectId::parse(&output.source.name).map_err(|error| {
                        SchedulerError::BoundaryViolation {
                            message: format!(
                                "network frame producer `{}` is not a canonical fault object: {error}",
                                output.source.name
                            ),
                        }
                    })?;
                    if frontier.ticks < output.fault_continuation.cursor().not_before_nanos() {
                        return Err(SchedulerError::BoundaryViolation {
                            message: format!(
                                "network frame {} resumed at {} before its adapter release coordinate {}",
                                output.sequence,
                                frontier.ticks,
                                output.fault_continuation.cursor().not_before_nanos()
                            ),
                        });
                    }
                    let mut admitted = true;
                    let mut resolved_effects =
                        output.fault_continuation.resolved_frame_effects().clone();
                    for stage in &stages {
                        for phase in stage.phases().iter().copied() {
                            if output
                                .fault_continuation
                                .cursor()
                                .is_complete(&stage.target, phase)
                            {
                                continue;
                            }
                            let length_bytes =
                                u64::try_from(output.payload.len()).map_err(|_error| {
                                    SchedulerError::BoundaryViolation {
                                        message: String::from(
                                            "network frame length exceeds the fault ABI width",
                                        ),
                                    }
                                })?;
                            let payload = OpportunityPayload::NetworkFrame {
                                producer: producer.clone(),
                                destination: FaultObjectId::parse(&route.destination.name)
                                    .map_err(|error| {
                                        SchedulerError::BoundaryViolation {
                                        message: format!(
                                            "network frame recipient `{}` is not a canonical fault object: {error}",
                                            route.destination.name
                                        ),
                                        }
                                    })?,
                                producer_sequence: output.sequence,
                                protocol_expansion_path: output
                                    .fault_continuation
                                    .protocol_expansion_path()
                                    .to_vec(),
                                generated_response_depth: output
                                    .fault_continuation
                                    .generated_response_depth(),
                                generated_response_cause: output
                                    .fault_continuation
                                    .generated_response_cause(),
                                forwarding_mutation_path: output
                                    .fault_continuation
                                    .forwarding_mutation_path()
                                    .to_vec(),
                                length_bytes,
                                payload_digest: ContentHash::from_bytes(&output.payload),
                            };
                            let opportunity = FaultOpportunity::new(
                                stage.target.clone(),
                                stage.operation,
                                phase,
                                FaultCoordinate {
                                    virtual_nanos: frontier.ticks,
                                    retired_instructions: Some(output.emit_icount.retired),
                                },
                                output.sequence,
                                Some(stage.direction),
                                payload.clone(),
                            )
                            .map_err(|error| {
                                SchedulerError::BoundaryViolation {
                                    message: format!(
                                        "construct network admission opportunity: {error}"
                                    ),
                                }
                            })?;
                            let sequence = self.next_sequence(frontier.ticks)?;
                            let host_before = self.runtime.host_state().clone();
                            let evaluation = self
                                .runtime
                                .evaluate_opportunity(&opportunity, sequence, _backend)
                                .map_err(|error| SchedulerError::BoundaryViolation {
                                    message: format!(
                                        "signal network opportunity failed closed: {error}"
                                    ),
                                })?;
                            runtime_committed = true;
                            next_wakeup_nanos =
                                earliest_wakeup(next_wakeup_nanos, evaluation.next_wakeup_nanos);
                            let impulses = self.runtime.drain_host_impulses();
                            let (transition_observations, records) = self
                                .stage_availability_transition_drops(
                                    opportunity.coordinate(),
                                    &evaluation.actions,
                                    &host_before,
                                    &mut staged_scheduler,
                                    &mut staged_pending,
                                    Some(&mut routed),
                                )?;
                            observations.extend(evaluation.observations);
                            observations.extend(transition_observations);
                            transition_records.extend(records);
                            let mut frame_actions = Vec::new();
                            staged_effect_state.boundary.apply_frame(
                                opportunity.target(),
                                output.fault_continuation.cursor().route_path_version(),
                                &self.topology,
                                frontier.ticks,
                                &mut resolved_effects,
                            )?;
                            for action in self
                                .runtime
                                .host_state()
                                .matching(opportunity.target(), phase)
                            {
                                if output.fault_continuation.preserves_availability(
                                    &action.binding,
                                    &action.target,
                                    phase,
                                    action.transition_sequence,
                                ) {
                                    continue;
                                }
                                let EffectSpecification::Network(
                                    NetworkEffectSpecification::Availability { state, .. },
                                ) = action.effect.specification()
                                else {
                                    frame_actions.push(action.clone());
                                    continue;
                                };
                                admitted &= availability_allows(*state, stage.direction);
                            }
                            for action in &impulses {
                                if action.target != *opportunity.target()
                                    || action.phase != phase
                                    || action.opportunity != Some(opportunity.id())
                                {
                                    return Err(SchedulerError::BoundaryViolation {
                                        message: format!(
                                            "network impulse `{}` does not match its exact opportunity",
                                            action.binding
                                        ),
                                    });
                                }
                                frame_actions.push(action.clone());
                            }
                            let application = if !frame_actions.is_empty() {
                                let base_rate_bps = output
                                    .route
                                    .as_ref()
                                    .and_then(|selected| {
                                        self.links.iter().find(|link| {
                                            let (left, right) = link.endpoints();
                                            crucible::LinkId::for_endpoints(left, right)
                                                == selected.link
                                        })
                                    })
                                    .and_then(crucible::LinkDef::bandwidth_bps);
                                let repeated_phase_effect =
                                    output.fault_continuation.cursor().repeated_phase_effect();
                                apply_network_frame_actions(
                                    &mut output.payload,
                                    &mut resolved_effects,
                                    &frame_actions,
                                    &opportunity,
                                    self.runtime.scenario_seed().ok_or_else(|| {
                                        SchedulerError::BoundaryViolation {
                                            message: String::from(
                                                "production network runtime omitted its scenario seed",
                                            ),
                                        }
                                    })?,
                                    &self.topology,
                                    &mut staged_effect_state,
                                    &mut staged_pending,
                                    base_rate_bps,
                                    repeated_phase_effect,
                                )?
                            } else {
                                NetworkFrameApplication::default()
                            };
                            if application.repeat_effect_on_resume.is_none() {
                                output
                                    .fault_continuation
                                    .cursor_mut()
                                    .complete(stage.target.clone(), phase)
                                    .map_err(|error| SchedulerError::BoundaryViolation {
                                        message: format!(
                                            "network fault continuation cursor failed: {error}"
                                        ),
                                    })?;
                            }
                            next_wakeup_nanos =
                                earliest_wakeup(next_wakeup_nanos, application.next_wakeup_nanos);
                            if let Some(response) = application.typed_response.as_ref() {
                                if !resolved_effects.is_dropped() {
                                    return Err(SchedulerError::BoundaryViolation {
                                        message: String::from(
                                            "typed network response did not reject its forward frame",
                                        ),
                                    });
                                }
                                let response_wakeup = stage_typed_network_response(
                                    &staged_scheduler,
                                    &mut staged_pending,
                                    &self.topology,
                                    &output,
                                    &route,
                                    response,
                                    opportunity.id(),
                                    frontier,
                                )?;
                                next_wakeup_nanos =
                                    earliest_wakeup(next_wakeup_nanos, response_wakeup);
                                continue 'route;
                            }
                            if let Some(recipients) = application.forwarding_recipients.as_ref() {
                                output
                                    .fault_continuation
                                    .set_resolved_frame_effects(resolved_effects.clone());
                                for recipient in recipients {
                                    let recipient = crucible::NodeId {
                                        name: recipient.as_str().to_owned(),
                                    };
                                    let mut rerouted = output.clone();
                                    rerouted.destination = recipient.clone();
                                    rerouted.route = None;
                                    rerouted.fault_continuation = output
                                        .fault_continuation
                                        .forwarding_mutation(opportunity.id(), recipient)
                                        .ok_or_else(|| SchedulerError::BoundaryViolation {
                                            message: format!(
                                                "network forwarding mutation exceeds depth bound {}",
                                                crucible::model::HARD_NETWORK_FORWARDING_MUTATION_DEPTH
                                            ),
                                        })?;
                                    staged_scheduler.resolve_backend_network_routes(&rerouted)?;
                                    stage_pending_network_output(&mut staged_pending, rerouted)?;
                                }
                                continue 'route;
                            }
                            if !application.expanded_payloads.is_empty() {
                                if admitted && !resolved_effects.is_dropped() {
                                    resolved_effects.require_serialization();
                                    output
                                        .fault_continuation
                                        .set_resolved_frame_effects(resolved_effects.clone());
                                    for (ordinal, payload) in
                                        application.expanded_payloads.into_iter().enumerate()
                                    {
                                        let mut fragment = output.clone();
                                        fragment.payload = payload;
                                        if fragment
                                            .fault_continuation
                                            .protocol_expansion_path()
                                            .len()
                                            >= crucible::model::HARD_NETWORK_PROTOCOL_EXPANSION_DEPTH
                                        {
                                            return Err(SchedulerError::BoundaryViolation {
                                                message: String::from(
                                                    "network protocol-expansion depth exceeds its hard bound",
                                                ),
                                            });
                                        }
                                        fragment
                                            .fault_continuation
                                            .append_protocol_expansion_ordinal(
                                                u16::try_from(ordinal).map_err(|_error| {
                                                    SchedulerError::BoundaryViolation {
                                                        message: String::from(
                                                            "network fragment ordinal exceeds u16",
                                                        ),
                                                    }
                                                })?,
                                            );
                                        stage_pending_network_output(
                                            &mut staged_pending,
                                            fragment,
                                        )?;
                                    }
                                }
                                continue 'route;
                            }
                            if let Some(not_before_nanos) = application.defer_until {
                                if not_before_nanos <= frontier.ticks {
                                    return Err(SchedulerError::BoundaryViolation {
                                        message: format!(
                                            "network queue deferred frame {} to nonfuture coordinate {not_before_nanos}",
                                            output.sequence
                                        ),
                                    });
                                }
                                if let Some(effect) = application.repeat_effect_on_resume {
                                    output
                                        .fault_continuation
                                        .cursor_mut()
                                        .defer_repeated_effect_until(
                                            not_before_nanos,
                                            opportunity.id(),
                                            effect,
                                            application.queue_priority,
                                        );
                                } else {
                                    output
                                        .fault_continuation
                                        .cursor_mut()
                                        .defer_until(not_before_nanos, opportunity.id());
                                }
                                output
                                    .fault_continuation
                                    .set_resolved_frame_effects(resolved_effects);
                                stage_pending_network_output(&mut staged_pending, output)?;
                                continue 'route;
                            }
                        }
                    }
                    if admitted {
                        output
                            .fault_continuation
                            .set_resolved_frame_effects(resolved_effects);
                        routed.push(output);
                    }
                }
            }
            if next_wakeup_nanos.is_some() {
                staged_scheduler.set_signal_fault_wakeup(next_wakeup_nanos)?;
            }
            let appends = if observations.is_empty() {
                Vec::new()
            } else {
                vec![staged_scheduler.append_fault_observations(observations)?]
            };
            Ok(appends)
        })();
        let appends = match staged {
            Ok(appends) => appends,
            Err(error) => {
                if runtime_committed {
                    self.runtime.poison();
                } else {
                    (self.coordinate, self.coordinate_sequence) = cursor_before;
                }
                return Err(error);
            }
        };
        *loop_impl = staged_scheduler;
        *pending_outputs = staged_pending;
        *outputs = routed;
        self.effect_state = staged_effect_state;
        for record in transition_records {
            self.transition_ledger.insert(record.action, record);
        }
        Ok(appends)
    }
}

pub(super) fn earliest_wakeup(current: Option<u64>, candidate: Option<u64>) -> Option<u64> {
    match (current, candidate) {
        (Some(current), Some(candidate)) => Some(current.min(candidate)),
        (Some(current), None) => Some(current),
        (None, candidate) => candidate,
    }
}

pub(super) fn apply_network_custody_removals(
    state: &mut NetworkEffectRuntimeState,
    pending_outputs: &mut [crucible::BackendNetworkOutput],
    actions: &[ResolvedBindingAction],
    now: u64,
) -> Result<bool, SchedulerError> {
    let mut released_due = false;
    for action in actions.iter().filter(|action| {
        action.kind == BindingActionKind::RemovePersistent
            && action.effect.kind() == crucible::model::EffectKind::NetworkCustodyQueue
    }) {
        let Some(queue) = state
            .custody_queues
            .remove(&NetworkEffectStateKey::from_action(action))
        else {
            continue;
        };
        let opportunities = queue
            .reservations
            .iter()
            .map(|reservation| reservation.opportunity)
            .chain(
                queue
                    .overflow_timeouts
                    .iter()
                    .map(|timeout| timeout.opportunity),
            )
            .collect::<BTreeSet<_>>();
        cancel_network_contact_reservations(
            &mut state.contact_services,
            &NetworkEffectStateKey::from_action(action),
            &opportunities,
            now,
            action,
        )?;
        for opportunity in queue
            .reservations
            .iter()
            .map(|reservation| reservation.opportunity)
            .chain(
                queue
                    .overflow_timeouts
                    .iter()
                    .map(|timeout| timeout.opportunity),
            )
        {
            let output = pending_outputs
                .iter_mut()
                .find(|output| {
                    output.fault_continuation.cursor().queue_opportunity() == Some(opportunity)
                })
                .ok_or_else(|| {
                    network_effect_application_error(
                        action,
                        "removed custody entry has no scheduler-owned pending frame",
                    )
                })?;
            output
                .fault_continuation
                .cursor_mut()
                .reschedule_queue_until(opportunity, now)
                .map_err(|error| network_effect_application_error(action, &error.to_string()))?;
            let mut effects = output.fault_continuation.resolved_frame_effects().clone();
            effects.require_serialization();
            output
                .fault_continuation
                .set_resolved_frame_effects(effects);
            released_due = true;
        }
    }
    Ok(released_due)
}

fn cancel_network_contact_reservations(
    services: &mut BTreeMap<NetworkContactServiceKey, NetworkContactServiceState>,
    owner: &NetworkEffectStateKey,
    opportunities: &BTreeSet<ContentHash>,
    now: u64,
    action: &impl NetworkEffectContext,
) -> Result<(), SchedulerError> {
    for (key, service) in services {
        service.settled_cursor_nanos = service.settled_cursor_nanos.max(key.start_nanos);
        let (removed_bundles, removed_bytes) = service
            .reservations
            .iter()
            .filter(|reservation| {
                reservation.custody_owner.as_ref() == Some(owner)
                    && opportunities.contains(&reservation.opportunity)
                    && reservation.finish_nanos > now
            })
            .try_fold((0_u64, 0_u64), |(bundles, bytes), reservation| {
                bundles
                    .checked_add(1)
                    .zip(bytes.checked_add(reservation.bytes))
            })
            .ok_or_else(|| {
                network_effect_application_error(action, "contact cancellation count overflowed")
            })?;
        service.reservations.retain(|reservation| {
            reservation.custody_owner.as_ref() != Some(owner)
                || !opportunities.contains(&reservation.opportunity)
                || reservation.finish_nanos <= now
        });
        service.settled_cursor_nanos = service.settled_cursor_nanos.max(
            service
                .reservations
                .iter()
                .filter(|reservation| reservation.finish_nanos <= now)
                .map(|reservation| reservation.finish_nanos)
                .max()
                .unwrap_or(key.start_nanos),
        );
        service.reservations.retain(|reservation| {
            reservation.finish_nanos > now
                || reservation.custody_owner.as_ref() != Some(owner)
                || !opportunities.contains(&reservation.opportunity)
        });
        service.served_bundles = service
            .served_bundles
            .checked_sub(removed_bundles)
            .ok_or_else(|| {
                network_effect_application_error(action, "contact bundle cancellation underflowed")
            })?;
        service.served_bytes =
            service
                .served_bytes
                .checked_sub(removed_bytes)
                .ok_or_else(|| {
                    network_effect_application_error(
                        action,
                        "contact byte cancellation underflowed",
                    )
                })?;
        service.service_cursor_nanos = service.settled_cursor_nanos.max(
            service
                .reservations
                .iter()
                .map(|reservation| reservation.finish_nanos)
                .max()
                .unwrap_or(key.start_nanos),
        );
    }
    Ok(())
}

fn prune_network_contact_services(state: &mut NetworkEffectRuntimeState, now: u64) {
    let live_custody = state
        .custody_queues
        .iter()
        .flat_map(|(owner, queue)| {
            queue
                .reservations
                .iter()
                .map(|reservation| (owner.clone(), reservation.opportunity))
        })
        .collect::<BTreeSet<_>>();
    for (key, service) in &mut state.contact_services {
        service.settled_cursor_nanos = service.settled_cursor_nanos.max(key.start_nanos);
        service.reservations.retain(|reservation| {
            let live = reservation.custody_owner.as_ref().is_some_and(|owner| {
                live_custody.contains(&(owner.clone(), reservation.opportunity))
            });
            if reservation.finish_nanos <= now && !live {
                service.settled_cursor_nanos =
                    service.settled_cursor_nanos.max(reservation.finish_nanos);
                false
            } else {
                true
            }
        });
        service.service_cursor_nanos = service.settled_cursor_nanos.max(
            service
                .reservations
                .iter()
                .map(|reservation| reservation.finish_nanos)
                .max()
                .unwrap_or(key.start_nanos),
        );
    }
}

fn network_contact_reservation_count(state: &NetworkEffectRuntimeState) -> Option<usize> {
    state
        .contact_services
        .values()
        .try_fold(0_usize, |total, service| {
            total.checked_add(service.reservations.len())
        })
}

fn network_contact_service_state_capacity_allows(current: usize, additional: usize) -> bool {
    current
        .checked_add(additional)
        .is_some_and(|count| count <= HARD_CONTACT_SERVICE_STATES)
}

fn admit_network_contact_service_keys(
    state: &NetworkEffectRuntimeState,
    keys: &BTreeSet<NetworkContactServiceKey>,
    action: &impl NetworkEffectContext,
) -> Result<(), SchedulerError> {
    let additional = keys
        .iter()
        .filter(|key| !state.contact_services.contains_key(*key))
        .count();
    if !network_contact_service_state_capacity_allows(state.contact_services.len(), additional) {
        return Err(network_effect_application_error(
            action,
            "contact service state exceeds 262,144 keyed cursors",
        ));
    }
    Ok(())
}

pub(super) fn availability_allows(
    state: NetworkAvailabilityState,
    direction: crucible::model::FaultDirection,
) -> bool {
    match state {
        NetworkAvailabilityState::Up => true,
        NetworkAvailabilityState::Down => false,
        NetworkAvailabilityState::ReceiveOnly => {
            direction == crucible::model::FaultDirection::Ingress
        }
        NetworkAvailabilityState::TransmitOnly => {
            direction == crucible::model::FaultDirection::Egress
        }
    }
}

fn apply_network_frame_actions(
    payload: &mut Vec<u8>,
    effects: &mut crucible::ResolvedNetworkFrameEffects,
    actions: &[ResolvedBindingAction],
    opportunity: &FaultOpportunity,
    scenario_seed: ContentHash,
    topology: &crucible::model::WorldFaultTopology,
    state: &mut NetworkEffectRuntimeState,
    pending_outputs: &mut Vec<crucible::BackendNetworkOutput>,
    base_rate_bps: Option<u64>,
    repeated_phase_effect: Option<crucible::model::EffectKind>,
) -> Result<NetworkFrameApplication, SchedulerError> {
    let actions = actions
        .iter()
        .filter(|action| repeated_phase_effect.is_none_or(|effect| action.effect.kind() == effect))
        .cloned()
        .collect::<Vec<_>>();
    let actions = actions.as_slice();
    if opportunity.phase() == FaultPhase::Queue {
        let custody_count = actions
            .iter()
            .filter(|action| {
                action.effect.kind() == crucible::model::EffectKind::NetworkCustodyQueue
            })
            .count();
        if custody_count > 1 {
            let action = actions
                .iter()
                .find(|action| {
                    action.effect.kind() == crucible::model::EffectKind::NetworkCustodyQueue
                })
                .ok_or_else(|| SchedulerError::BoundaryViolation {
                    message: String::from("custody conflict lost its owning action"),
                })?;
            return Err(network_effect_application_error(
                action,
                "multiple custody queues survived conflict composition",
            ));
        }
        let queue_policy_count = actions
            .iter()
            .filter(|action| {
                action.effect.kind() == crucible::model::EffectKind::NetworkQueuePolicy
            })
            .count();
        if queue_policy_count > 1 {
            let action = actions
                .iter()
                .find(|action| {
                    action.effect.kind() == crucible::model::EffectKind::NetworkQueuePolicy
                })
                .ok_or_else(|| SchedulerError::BoundaryViolation {
                    message: String::from("queue-policy conflict lost its owning action"),
                })?;
            return Err(network_effect_application_error(
                action,
                "multiple queue policies survived conflict composition",
            ));
        }
    }
    let mut deferred_until = None;
    let mut queue_policy = None;
    let mut service_curves = Vec::new();
    let mut mtu_policy: Option<(&ResolvedBindingAction, &NetworkEffectSpecification)> = None;
    let mut typed_response = None;
    let mut forwarding_recipients = None;
    let mut state_machine_wakeup = None;
    let mut repeat_effect_on_resume = None;
    let mut queue_priority = None;
    let backpressure_wakeup = apply_network_backpressure_transitions(
        state,
        pending_outputs,
        actions,
        topology,
        opportunity.coordinate().virtual_nanos,
    )?;
    for action in actions {
        let EffectSpecification::Network(specification) = action.effect.specification() else {
            return Err(network_effect_application_error(
                action,
                "non-network effect reached the network adapter",
            ));
        };
        match specification {
            NetworkEffectSpecification::ServiceCurve { segments } => {
                service_curves.push(NetworkServiceCurveState {
                    activation_nanos: action.coordinate.virtual_nanos,
                    segments: segments.as_slice().to_vec(),
                });
            }
            NetworkEffectSpecification::TokenBucket {
                rate_bps,
                burst_bits,
                initial_bits,
            } => {
                let delay = apply_network_token_bucket(
                    state,
                    action,
                    opportunity,
                    payload.len(),
                    rate_bps.get(),
                    burst_bits.get(),
                    *initial_bits,
                )?;
                deferred_until = latest_wakeup(
                    deferred_until,
                    opportunity.coordinate().virtual_nanos.checked_add(delay),
                );
            }
            NetworkEffectSpecification::BurstErrorState {
                good_to_bad,
                bad_to_good,
                state_parameters,
            } => apply_network_burst_error(
                payload,
                effects,
                state,
                action,
                opportunity,
                scenario_seed,
                topology,
                *good_to_bad,
                *bad_to_good,
                state_parameters,
            )?,
            NetworkEffectSpecification::PauseBackpressure { .. } => {}
            NetworkEffectSpecification::Mtu { .. } => {
                if let Some((existing, existing_specification)) = mtu_policy {
                    let NetworkEffectSpecification::Mtu {
                        mtu_bytes: existing_mtu,
                        oversize: existing_oversize,
                        fragmentation_protocol: existing_protocol,
                        typed_error: existing_error,
                    } = existing_specification
                    else {
                        return Err(network_effect_application_error(
                            action,
                            "MTU composition lost its typed parameters",
                        ));
                    };
                    let NetworkEffectSpecification::Mtu {
                        mtu_bytes,
                        oversize,
                        fragmentation_protocol,
                        typed_error,
                    } = specification
                    else {
                        return Err(network_effect_application_error(
                            action,
                            "MTU composition received non-MTU parameters",
                        ));
                    };
                    if existing_oversize != oversize
                        || existing_protocol != fragmentation_protocol
                        || existing_error != typed_error
                    {
                        return Err(network_effect_application_error(
                            action,
                            "simultaneous MTU effects disagree on oversize disposition",
                        ));
                    }
                    mtu_policy = Some(if mtu_bytes.get() < existing_mtu.get() {
                        (action, specification)
                    } else {
                        (existing, existing_specification)
                    });
                } else {
                    mtu_policy = Some((action, specification));
                }
            }
            NetworkEffectSpecification::QueuePolicy { .. }
                if opportunity.phase() == FaultPhase::Queue =>
            {
                if queue_policy.replace((action, specification)).is_some() {
                    return Err(network_effect_application_error(
                        action,
                        "multiple queue policies survived conflict composition",
                    ));
                }
            }
            NetworkEffectSpecification::QueuePolicy { .. } => {}
            NetworkEffectSpecification::FirewallDisposition {
                action: disposition,
                typed_reject,
                rule,
                state_machine,
                transition_event,
            } => {
                if action.kind == BindingActionKind::RemovePersistent {
                    state
                        .state_machines
                        .remove(&NetworkEffectStateKey::from_action(action));
                    continue;
                }
                let release = apply_network_firewall(
                    payload,
                    effects,
                    state,
                    topology,
                    action,
                    opportunity,
                    *disposition,
                    typed_reject.as_ref(),
                    rule,
                    state_machine,
                    transition_event,
                    &mut typed_response,
                )?;
                state_machine_wakeup = earliest_wakeup(state_machine_wakeup, release);
            }
            NetworkEffectSpecification::ConnectionState {
                table_bound,
                flow_key,
                state_machine,
                transition_event,
                overflow,
                ..
            } => {
                if action.kind == BindingActionKind::RemovePersistent {
                    state
                        .connection_tables
                        .remove(&NetworkEffectStateKey::from_action(action));
                    continue;
                }
                let release = apply_network_connection_state(
                    payload,
                    effects,
                    state,
                    topology,
                    action,
                    opportunity,
                    scenario_seed,
                    table_bound.get(),
                    flow_key,
                    state_machine,
                    transition_event,
                    overflow,
                    &mut typed_response,
                )?;
                state_machine_wakeup = earliest_wakeup(state_machine_wakeup, release);
            }
            NetworkEffectSpecification::SharedMedium {
                resources,
                policy,
                transmit_power_femtowatts,
            } => {
                let service_rate = effects.serialization_rate_cap_bps().or(base_rate_bps);
                let release = apply_network_shared_medium(
                    payload,
                    effects,
                    state,
                    pending_outputs,
                    topology,
                    action,
                    opportunity,
                    scenario_seed,
                    resources,
                    policy,
                    transmit_power_femtowatts.get(),
                    service_rate,
                )?;
                deferred_until = latest_wakeup(deferred_until, release);
            }
            NetworkEffectSpecification::CustodyQueue {
                capacity_bytes,
                capacity_bundles,
                expiry_nanos,
                custody_policy,
                route_contact_plan,
                priority,
                max_visited_hops,
            } if opportunity.phase() == FaultPhase::Queue => {
                let application = apply_network_custody_queue(
                    payload,
                    effects,
                    state,
                    pending_outputs,
                    topology,
                    action,
                    opportunity,
                    capacity_bytes.get(),
                    u64::from(capacity_bundles.get()),
                    expiry_nanos.get(),
                    custody_policy,
                    route_contact_plan,
                    *priority,
                    max_visited_hops.get(),
                    &mut typed_response,
                )?;
                deferred_until = latest_wakeup(deferred_until, application.defer_until);
                if application.repeat_phase_on_resume {
                    repeat_effect_on_resume =
                        Some(crucible::model::EffectKind::NetworkCustodyQueue);
                    queue_priority = Some(priority.rank());
                }
            }
            NetworkEffectSpecification::CustodyQueue { .. } => {}
            NetworkEffectSpecification::ForwardingMutation { selector, mutation } => {
                apply_network_forwarding_mutation(
                    payload,
                    topology,
                    action,
                    opportunity,
                    selector,
                    mutation,
                    &mut forwarding_recipients,
                )?;
                if forwarding_recipients.is_some() {
                    effects.mark_drop();
                }
            }
            _ => apply_network_frame_action(
                payload,
                effects,
                action,
                opportunity,
                scenario_seed,
                topology,
                state,
            )?,
        }
    }
    let expanded_payloads = if let Some((action, specification)) = mtu_policy {
        apply_network_mtu(payload, effects, action, specification, &mut typed_response)?
    } else {
        None
    };
    if let Some(expanded_payloads) = expanded_payloads {
        return Ok(NetworkFrameApplication {
            expanded_payloads,
            typed_response,
            next_wakeup_nanos: earliest_wakeup(
                state
                    .boundary
                    .next_wakeup_nanos(opportunity.coordinate().virtual_nanos),
                backpressure_wakeup,
            ),
            ..NetworkFrameApplication::default()
        });
    }
    if let Some((
        action,
        NetworkEffectSpecification::QueuePolicy {
            capacity_bytes,
            capacity_frames,
            discipline,
            discipline_parameters,
            overflow,
            typed_error,
        },
    )) = queue_policy
    {
        let service_rate = effects.serialization_rate_cap_bps().or(base_rate_bps);
        let release = apply_network_queue_policy(
            state,
            pending_outputs,
            effects,
            action,
            opportunity,
            scenario_seed,
            topology,
            payload,
            capacity_bytes.get(),
            u64::from(capacity_frames.get()),
            *discipline,
            discipline_parameters.as_ref(),
            *overflow,
            typed_error.as_ref(),
            &mut typed_response,
            service_rate,
            &service_curves,
            deferred_until,
        )?;
        deferred_until = latest_wakeup(deferred_until, release);
    } else if !service_curves.is_empty() {
        let action = actions
            .iter()
            .find(|action| {
                matches!(
                    action.effect.specification(),
                    EffectSpecification::Network(NetworkEffectSpecification::ServiceCurve { .. })
                )
            })
            .ok_or_else(|| SchedulerError::BoundaryViolation {
                message: String::from("network service curve lost its owning action"),
            })?;
        let release = apply_network_queue_policy(
            state,
            pending_outputs,
            effects,
            action,
            opportunity,
            scenario_seed,
            topology,
            payload,
            u64::try_from(HARD_PENDING_NETWORK_BYTES).map_err(|_error| {
                network_effect_application_error(action, "pending byte bound exceeds u64")
            })?,
            u64::try_from(HARD_PENDING_NETWORK_FRAMES).map_err(|_error| {
                network_effect_application_error(action, "pending frame bound exceeds u64")
            })?,
            crucible::model::NetworkQueueDiscipline::Fifo,
            None,
            crucible::model::NetworkQueueOverflow::TailDrop,
            None,
            &mut typed_response,
            effects.serialization_rate_cap_bps().or(base_rate_bps),
            &service_curves,
            deferred_until,
        )?;
        deferred_until = latest_wakeup(deferred_until, release);
    }
    let defer_until =
        deferred_until.filter(|coordinate| *coordinate > opportunity.coordinate().virtual_nanos);
    Ok(NetworkFrameApplication {
        defer_until,
        repeat_effect_on_resume,
        queue_priority,
        next_wakeup_nanos: earliest_wakeup(
            earliest_wakeup(defer_until, state_machine_wakeup),
            earliest_wakeup(
                state
                    .boundary
                    .next_wakeup_nanos(opportunity.coordinate().virtual_nanos),
                backpressure_wakeup,
            ),
        ),
        expanded_payloads: Vec::new(),
        typed_response,
        forwarding_recipients,
    })
}

#[derive(Clone, Debug, Default)]
struct NetworkFrameApplication {
    defer_until: Option<u64>,
    repeat_effect_on_resume: Option<crucible::model::EffectKind>,
    queue_priority: Option<u8>,
    next_wakeup_nanos: Option<u64>,
    expanded_payloads: Vec<Vec<u8>>,
    typed_response: Option<FaultObjectId>,
    forwarding_recipients: Option<Vec<FaultObjectId>>,
}

fn apply_network_forwarding_mutation(
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
fn apply_network_firewall(
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
fn apply_network_connection_state(
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

fn network_packet_key(
    payload: &[u8],
    topology: &crucible::model::WorldFaultTopology,
    key: &FaultObjectId,
    action: &ResolvedBindingAction,
) -> Result<ContentHash, SchedulerError> {
    Ok(ContentHash::from_bytes(&network_packet_key_bytes(
        payload, topology, key, action,
    )?))
}

fn network_packet_key_bytes(
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
fn apply_network_shared_medium(
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

fn intervals_overlap(left_start: u64, left_end: u64, right_start: u64, right_end: u64) -> bool {
    left_start < right_end && right_start < left_end
}

fn reschedule_medium_output(
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

fn drop_medium_output(
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

fn transform_medium_output(
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

fn pending_medium_output<'a>(
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

fn xor_repeated(payload: &mut [u8], transform: &[u8]) {
    for (index, byte) in payload.iter_mut().enumerate() {
        *byte ^= transform[index % transform.len()];
    }
}

#[allow(clippy::too_many_arguments)]
fn apply_medium_capture(
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

fn network_state_machine_initial(
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

fn advance_network_state_machine(
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
fn stage_typed_network_response(
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

fn device_response_specification(
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

fn request_typed_response(
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

fn apply_network_mtu(
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

fn apply_network_pause_action(
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

fn next_network_pause_wakeup(
    pauses: &BTreeMap<NetworkEffectStateKey, NetworkPauseState>,
    now: u64,
) -> Option<u64> {
    pauses
        .values()
        .filter_map(|pause| pause.paused_until)
        .filter(|until| *until > now)
        .min()
}

pub(super) fn apply_network_backpressure_transitions(
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
fn apply_network_queue_policy(
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

fn network_queue_discipline<'a>(
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

fn network_queue_class(
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

fn network_pause_boundary(
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

fn retire_network_queue(
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
fn reschedule_network_queue(
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
    {
        if let Some(active) = active.take() {
            reservations.push(active);
        }
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

pub(super) fn network_service_finish(
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

fn network_service_finish_demand(
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

fn network_service_capacity(
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

fn add_projected_queue_service(
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

fn compare_queue_candidates(
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

fn latest_wakeup(current: Option<u64>, candidate: Option<u64>) -> Option<u64> {
    match (current, candidate) {
        (Some(current), Some(candidate)) => Some(current.max(candidate)),
        (Some(current), None) => Some(current),
        (None, candidate) => candidate,
    }
}

#[allow(clippy::too_many_arguments)]
fn apply_network_token_bucket(
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
        return u64::try_from(service_base - now)
            .map_err(|_error| network_effect_application_error(action, "token delay exceeds u64"));
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

fn ceil_ratio_u128(numerator: u128, denominator: u128) -> Option<u128> {
    numerator
        .checked_add(denominator.checked_sub(1)?)
        .map(|value| value / denominator)
}

#[allow(clippy::too_many_arguments)]
fn apply_network_burst_error(
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

#[derive(Clone, Copy, Debug, Default)]
struct NetworkCustodyApplication {
    defer_until: Option<u64>,
    repeat_phase_on_resume: bool,
}

fn network_bundle_identity(
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

fn contact_traffic_bounds(
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
fn reserve_network_contact_service(
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
struct NetworkContactRouteLabel {
    node: FaultObjectId,
    arrival_nanos: u64,
    cost: u64,
    interval_indexes: Vec<usize>,
    contact_ids: Vec<FaultObjectId>,
    visited_nodes: BTreeSet<FaultObjectId>,
}

#[derive(Clone, Debug)]
struct NetworkContactRouteReservation {
    first_start_nanos: u64,
    finish_nanos: u64,
    contacts: Vec<FaultObjectId>,
    identities: Vec<[u8; 32]>,
}

fn preview_network_contact_service(
    state: &NetworkEffectRuntimeState,
    topology: &crucible::model::WorldFaultTopology,
    plan: &FaultObjectId,
    interval: &crucible::model::NetworkPolicyContactInterval,
    earliest_nanos: u64,
    payload_bytes: u64,
    action: &ResolvedBindingAction,
) -> Result<Option<(u64, u64, u64, NetworkContactServiceKey, [u8; 32])>, SchedulerError> {
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
fn reserve_network_contact_route(
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

fn contact_graph_has_path(
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
fn apply_network_custody_queue(
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

fn apply_network_frame_action(
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

pub(super) fn network_effect_application_error(
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

fn network_effect_draw(
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

fn probability_fires(probability: crucible::model::ProbabilityMillionths, draw: u64) -> bool {
    draw % 1_000_000 < u64::from(probability.get())
}

fn uniform_inclusive(draw: u64, maximum: u64) -> u64 {
    let range = u128::from(maximum) + 1;
    ((u128::from(draw) * range) >> 64) as u64
}

#[allow(clippy::too_many_arguments)]
fn apply_network_recipient_subset(
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

fn network_recipient_rank(
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

fn mapped_network_integer(action: &ResolvedBindingAction) -> Result<i64, SchedulerError> {
    mapped_network_integers(action)?
        .into_iter()
        .next()
        .ok_or_else(|| network_effect_application_error(action, "network lookup has no input"))
}

fn mapped_network_service_input(
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

fn mapped_network_service_u64(
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

fn multiply_ratio_millionths(
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

fn divide_ties_to_even(numerator: u128, denominator: u128) -> u128 {
    let quotient = numerator / denominator;
    let remainder = numerator % denominator;
    let half = denominator / 2;
    let above_half = remainder > half;
    let exactly_half = denominator % 2 == 0 && remainder == half;
    if above_half || exactly_half && quotient % 2 == 1 {
        quotient + 1
    } else {
        quotient
    }
}

pub(super) fn mapped_network_integers(
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

fn mapped_network_scalar(
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

fn network_policy_lookup(
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

pub(super) fn lookup_network_integer_table(
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

fn interpolate_network_policy(
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

fn network_byte_template<'a>(
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

fn apply_network_field_mutation(
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

fn network_packet_selector_matches(
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crucible::model::{
        BindingActionCause, BindingActionKind, CountLimit, EFFECT_SEMANTIC_VERSION, EffectLifetime,
        EffectRequest, NetworkInFlightPolicy, PositiveU64, ResolvedFaultTarget,
        ResolvedMappingOutput,
    };

    fn id(value: &str) -> FaultObjectId {
        FaultObjectId::parse(value)
            .unwrap_or_else(|error| panic!("test object ID should be valid: {error}"))
    }

    fn positive(value: u64) -> PositiveU64 {
        PositiveU64::new("test", value)
            .unwrap_or_else(|error| panic!("test positive value should be valid: {error}"))
    }

    fn action() -> ResolvedBindingAction {
        let effect = EffectRequest::new(
            EFFECT_SEMANTIC_VERSION,
            EffectLifetime::Persistent,
            EffectSpecification::Network(NetworkEffectSpecification::Availability {
                state: NetworkAvailabilityState::Up,
                queued_policy: NetworkInFlightPolicy::Preserve,
                in_flight_policy: NetworkInFlightPolicy::Preserve,
            }),
        )
        .unwrap_or_else(|error| panic!("test effect should be valid: {error}"));
        ResolvedBindingAction {
            kind: BindingActionKind::UpsertPersistent,
            binding: id("network-test-binding"),
            target: ResolvedFaultTarget::NetworkSegment {
                segment: id("network-test-segment"),
                direction: crucible::model::FaultDirection::AToB,
            },
            phase: FaultPhase::Queue,
            effect: Arc::new(effect),
            mapping_output: Arc::new(ResolvedMappingOutput::Activation { active: true }),
            mapped_digest: ContentHash::from_bytes(b"mapped"),
            transition_sequence: 1,
            opportunity: None,
            coordinate: FaultCoordinate {
                virtual_nanos: 0,
                retired_instructions: None,
            },
            cause: BindingActionCause::Signal,
        }
    }

    #[test]
    fn multicast_recipient_selection_is_shared_across_route_copies() {
        let action = action();
        let membership = id("multicast-members-v1");
        let mut topology = crucible::model::WorldFaultTopology::default();
        topology
            .network_policy_artifacts
            .push(crucible::model::WorldNetworkPolicyArtifact {
                id: membership.clone(),
                semantic_version: 1,
                artifact: crucible::model::NetworkPolicyArtifactKind::RecipientMembership {
                    members: vec![
                        crucible::model::NetworkPolicyRecipient {
                            member: id("receiver-a"),
                            joined_sequence: 1,
                        },
                        crucible::model::NetworkPolicyRecipient {
                            member: id("receiver-b"),
                            joined_sequence: 2,
                        },
                    ],
                },
            });
        let retain =
            crucible::model::BoundedCount::new(CountLimit::DuplicatesOrInstructionReplay, 1)
                .unwrap_or_else(|error| panic!("recipient count: {error}"));
        let mut outcomes = Vec::new();
        for destination in [id("receiver-a"), id("receiver-b")] {
            let opportunity = FaultOpportunity::new(
                action.target.clone(),
                crucible::model::FaultOperation::NetworkTraverse,
                FaultPhase::Deliver,
                FaultCoordinate {
                    virtual_nanos: 10,
                    retired_instructions: Some(1),
                },
                7,
                Some(crucible::model::FaultDirection::AToB),
                OpportunityPayload::NetworkFrame {
                    producer: id("sender"),
                    destination,
                    producer_sequence: 7,
                    protocol_expansion_path: Vec::new(),
                    generated_response_depth: 0,
                    generated_response_cause: None,
                    forwarding_mutation_path: Vec::new(),
                    length_bytes: 64,
                    payload_digest: ContentHash::from_bytes(b"multicast-frame"),
                },
            )
            .unwrap_or_else(|error| panic!("recipient opportunity: {error}"));
            let mut effects = crucible::ResolvedNetworkFrameEffects::default();
            apply_network_recipient_subset(
                &mut effects,
                &action,
                &opportunity,
                ContentHash::from_bytes(b"recipient-seed"),
                &topology,
                &membership,
                None,
                Some(&crucible::model::NetworkSelection::KeyedUniform),
                Some(&retain),
            )
            .unwrap_or_else(|error| panic!("recipient selection: {error}"));
            outcomes.push(effects.is_dropped());
        }

        assert_eq!(outcomes.iter().filter(|dropped| !**dropped).count(), 1);
    }

    fn opportunity(sequence: u64) -> FaultOpportunity {
        FaultOpportunity::new(
            ResolvedFaultTarget::NetworkSegment {
                segment: id("network-test-segment"),
                direction: crucible::model::FaultDirection::AToB,
            },
            crucible::model::FaultOperation::NetworkTraverse,
            FaultPhase::Queue,
            FaultCoordinate {
                virtual_nanos: 0,
                retired_instructions: None,
            },
            sequence,
            Some(crucible::model::FaultDirection::AToB),
            OpportunityPayload::NetworkFrame {
                producer: id("sender"),
                destination: id("receiver"),
                producer_sequence: sequence,
                protocol_expansion_path: Vec::new(),
                generated_response_depth: 0,
                generated_response_cause: None,
                forwarding_mutation_path: Vec::new(),
                length_bytes: 1,
                payload_digest: ContentHash::from_bytes(&[u8::try_from(sequence).unwrap_or(0)]),
            },
        )
        .unwrap_or_else(|error| panic!("test opportunity should be valid: {error}"))
    }

    fn action_with_network_effect(
        specification: NetworkEffectSpecification,
    ) -> ResolvedBindingAction {
        let mut action = action();
        let descriptor = specification.kind().descriptor();
        let lifetime = if descriptor.lifetimes.contains(&EffectLifetime::Opportunity) {
            EffectLifetime::Opportunity
        } else if descriptor.lifetimes.contains(&EffectLifetime::Impulse) {
            EffectLifetime::Impulse
        } else {
            descriptor.lifetimes[0]
        };
        action.kind = if lifetime == EffectLifetime::Persistent {
            BindingActionKind::UpsertPersistent
        } else {
            BindingActionKind::Apply
        };
        action.phase = descriptor.phases[0];
        action.effect = Arc::new(
            EffectRequest::new(
                EFFECT_SEMANTIC_VERSION,
                lifetime,
                EffectSpecification::Network(specification),
            )
            .unwrap_or_else(|error| panic!("test network effect: {error}")),
        );
        action
    }

    fn medium_action(
        resources: crucible::model::ObjectIdSet,
        policy: FaultObjectId,
        power: u64,
    ) -> ResolvedBindingAction {
        let mut action = action();
        action.target = ResolvedFaultTarget::NetworkMedium {
            medium: id("test-medium"),
            resource: id("test-channel"),
        };
        action.effect = Arc::new(
            EffectRequest::new(
                EFFECT_SEMANTIC_VERSION,
                EffectLifetime::Persistent,
                EffectSpecification::Network(NetworkEffectSpecification::SharedMedium {
                    resources,
                    policy,
                    transmit_power_femtowatts: positive(power),
                }),
            )
            .unwrap_or_else(|error| panic!("test shared-medium effect: {error}")),
        );
        action
    }

    fn medium_opportunity(producer: &str, sequence: u64, payload: &[u8]) -> FaultOpportunity {
        FaultOpportunity::new(
            ResolvedFaultTarget::NetworkMedium {
                medium: id("test-medium"),
                resource: id("test-channel"),
            },
            crucible::model::FaultOperation::NetworkTraverse,
            FaultPhase::Queue,
            FaultCoordinate {
                virtual_nanos: 0,
                retired_instructions: None,
            },
            sequence,
            Some(crucible::model::FaultDirection::AToB),
            OpportunityPayload::NetworkFrame {
                producer: id(producer),
                destination: id("receiver"),
                producer_sequence: sequence,
                protocol_expansion_path: Vec::new(),
                generated_response_depth: 0,
                generated_response_cause: None,
                forwarding_mutation_path: Vec::new(),
                length_bytes: u64::try_from(payload.len())
                    .unwrap_or_else(|error| panic!("test payload length: {error}")),
                payload_digest: ContentHash::from_bytes(payload),
            },
        )
        .unwrap_or_else(|error| panic!("test medium opportunity: {error}"))
    }

    fn medium_topology(
        policy_id: FaultObjectId,
        policy: crucible::model::NetworkPolicyMediumAccess,
        additional: Vec<crucible::model::WorldNetworkPolicyArtifact>,
    ) -> crucible::model::WorldFaultTopology {
        let mut topology = crucible::model::WorldFaultTopology::default();
        topology
            .network_policy_artifacts
            .push(crucible::model::WorldNetworkPolicyArtifact {
                id: policy_id,
                semantic_version: 1,
                artifact: crucible::model::NetworkPolicyArtifactKind::MediumAccess(policy),
            });
        topology.network_policy_artifacts.extend(additional);
        topology
            .network_policy_artifacts
            .sort_by(|left, right| left.id.cmp(&right.id));
        topology
    }

    fn medium_policy(
        arbitration: crucible::model::NetworkPolicyArbitration,
        collision: crucible::model::NetworkPolicyCollision,
    ) -> crucible::model::NetworkPolicyMediumAccess {
        crucible::model::NetworkPolicyMediumAccess {
            arbitration,
            arbitration_key: None,
            fixed_slot_nanos: None,
            contention: (arbitration == crucible::model::NetworkPolicyArbitration::Contention)
                .then_some(crucible::model::NetworkPolicyContention {
                    collision,
                    capture_threshold_millionths: (collision
                        == crucible::model::NetworkPolicyCollision::Capture)
                        .then_some(positive(1_000_000)),
                    undetected_transform: None,
                    backoff_slot_nanos: positive(100),
                    maximum_backoff_exponent: 8,
                    maximum_retries: 0,
                }),
            duty_cycle_numerator: positive(1),
            duty_cycle_denominator: positive(1),
        }
    }

    fn pending_medium_frame(
        opportunity: &FaultOpportunity,
        release: u64,
        effects: crucible::ResolvedNetworkFrameEffects,
        payload: Vec<u8>,
    ) -> crucible::BackendNetworkOutput {
        let OpportunityPayload::NetworkFrame {
            producer,
            destination,
            producer_sequence,
            ..
        } = opportunity.payload()
        else {
            panic!("test medium opportunity must carry a frame");
        };
        let mut continuation = crucible::BackendNetworkFaultContinuation::default();
        continuation
            .cursor_mut()
            .defer_until(release, opportunity.id());
        continuation.set_resolved_frame_effects(effects);
        crucible::BackendNetworkOutput {
            source: crucible::NodeId {
                name: producer.as_str().to_owned(),
            },
            destination: crucible::NodeId {
                name: destination.as_str().to_owned(),
            },
            emit_icount: crucible::Icount { retired: 0 },
            sequence: *producer_sequence,
            payload,
            route: None,
            fault_continuation: continuation,
        }
    }

    #[test]
    fn shared_medium_serial_arbitration_reschedules_by_declared_order() {
        let resources = crucible::model::ObjectIdSet::new(vec![id("sender-a"), id("sender-b")])
            .unwrap_or_else(|error| panic!("test medium resources: {error}"));
        for arbitration in [
            crucible::model::NetworkPolicyArbitration::Fifo,
            crucible::model::NetworkPolicyArbitration::StrictPriority,
            crucible::model::NetworkPolicyArbitration::CanDominantBit,
        ] {
            let policy_id = id("serial-medium-policy");
            let key_id = id("medium-arbitration-key");
            let mut policy = medium_policy(
                arbitration,
                crucible::model::NetworkPolicyCollision::DropAll,
            );
            let additional = if arbitration == crucible::model::NetworkPolicyArbitration::Fifo {
                Vec::new()
            } else {
                policy.arbitration_key = Some(key_id.clone());
                vec![crucible::model::WorldNetworkPolicyArtifact {
                    id: key_id,
                    semantic_version: 1,
                    artifact: crucible::model::NetworkPolicyArtifactKind::PacketKey {
                        ranges: vec![
                            crucible::model::ByteRange::new(0, 1)
                                .unwrap_or_else(|error| panic!("test packet key: {error}")),
                        ],
                    },
                }]
            };
            let topology = medium_topology(policy_id.clone(), policy, additional);
            let action = medium_action(resources.clone(), policy_id, 1);
            let first_opportunity = medium_opportunity("sender-a", 1, &[0xff]);
            let mut first_payload = vec![0xff];
            let mut first_effects = crucible::ResolvedNetworkFrameEffects::default();
            let mut state = NetworkEffectRuntimeState::default();
            let first_release = apply_network_shared_medium(
                &mut first_payload,
                &mut first_effects,
                &mut state,
                &mut [],
                &topology,
                &action,
                &first_opportunity,
                ContentHash::from_bytes(b"serial-medium"),
                &resources,
                &id("serial-medium-policy"),
                1,
                Some(1_000_000_000),
            )
            .unwrap_or_else(|error| panic!("first serial contender: {error}"))
            .unwrap_or_else(|| panic!("first serial contender must defer"));
            assert_eq!(first_release, 8);
            let mut pending = vec![pending_medium_frame(
                &first_opportunity,
                first_release,
                first_effects,
                first_payload,
            )];
            let second_opportunity = medium_opportunity("sender-b", 2, &[0x00]);
            let mut second_payload = vec![0x00];
            let mut second_effects = crucible::ResolvedNetworkFrameEffects::default();
            let second_release = apply_network_shared_medium(
                &mut second_payload,
                &mut second_effects,
                &mut state,
                &mut pending,
                &topology,
                &action,
                &second_opportunity,
                ContentHash::from_bytes(b"serial-medium"),
                &resources,
                &id("serial-medium-policy"),
                1,
                Some(1_000_000_000),
            )
            .unwrap_or_else(|error| panic!("second serial contender: {error}"))
            .unwrap_or_else(|| panic!("second serial contender must defer"));
            if arbitration == crucible::model::NetworkPolicyArbitration::Fifo {
                assert_eq!(second_release, 16);
                assert_eq!(pending[0].fault_continuation.cursor().not_before_nanos(), 8);
            } else {
                assert_eq!(second_release, 8);
                assert_eq!(
                    pending[0].fault_continuation.cursor().not_before_nanos(),
                    16
                );
            }
            assert!(second_effects.serialization_is_accounted());
        }
    }

    #[test]
    fn shared_medium_fixed_slots_follow_canonical_resource_order() {
        let resources = crucible::model::ObjectIdSet::new(vec![id("sender-b"), id("sender-a")])
            .unwrap_or_else(|error| panic!("test medium resources: {error}"));
        let policy_id = id("fixed-medium-policy");
        let mut policy = medium_policy(
            crucible::model::NetworkPolicyArbitration::FixedSlots,
            crucible::model::NetworkPolicyCollision::DropAll,
        );
        policy.fixed_slot_nanos = Some(positive(10));
        let topology = medium_topology(policy_id.clone(), policy, Vec::new());
        let action = medium_action(resources.clone(), policy_id.clone(), 1);
        let mut state = NetworkEffectRuntimeState::default();
        let mut pending = Vec::new();
        let mut releases = Vec::new();
        for (producer, sequence) in [("sender-a", 1), ("sender-b", 2)] {
            let opportunity = medium_opportunity(producer, sequence, &[0]);
            let mut payload = vec![0];
            let mut effects = crucible::ResolvedNetworkFrameEffects::default();
            releases.push(
                apply_network_shared_medium(
                    &mut payload,
                    &mut effects,
                    &mut state,
                    &mut pending,
                    &topology,
                    &action,
                    &opportunity,
                    ContentHash::from_bytes(b"fixed-medium"),
                    &resources,
                    &policy_id,
                    1,
                    Some(1_000_000_000),
                )
                .unwrap_or_else(|error| panic!("fixed-slot contender: {error}"))
                .unwrap_or_else(|| panic!("fixed-slot contender must defer")),
            );
        }
        assert_eq!(releases, vec![8, 18]);
    }

    #[test]
    fn shared_medium_contention_retries_and_terminal_outcomes_are_exact() {
        let resources = crucible::model::ObjectIdSet::new(vec![id("sender-a"), id("sender-b")])
            .unwrap_or_else(|error| panic!("test medium resources: {error}"));
        let scenario_seed = ContentHash::from_bytes(b"contention-medium");
        let policy_id = id("contention-medium-policy");
        let mut retry_policy = medium_policy(
            crucible::model::NetworkPolicyArbitration::Contention,
            crucible::model::NetworkPolicyCollision::DropAll,
        );
        retry_policy
            .contention
            .as_mut()
            .unwrap_or_else(|| panic!("test contention policy must exist"))
            .maximum_retries = 1;
        let topology = medium_topology(policy_id.clone(), retry_policy, Vec::new());
        let action = medium_action(resources.clone(), policy_id.clone(), 1);
        let first_opportunity = medium_opportunity("sender-a", 1, &[1]);
        let mut first_payload = vec![1];
        let mut first_effects = crucible::ResolvedNetworkFrameEffects::default();
        let mut state = NetworkEffectRuntimeState::default();
        let first_release = apply_network_shared_medium(
            &mut first_payload,
            &mut first_effects,
            &mut state,
            &mut [],
            &topology,
            &action,
            &first_opportunity,
            scenario_seed,
            &resources,
            &policy_id,
            1,
            Some(1_000_000_000),
        )
        .unwrap_or_else(|error| panic!("first contention frame: {error}"))
        .unwrap_or_else(|| panic!("first contention frame must defer"));
        let mut pending = vec![pending_medium_frame(
            &first_opportunity,
            first_release,
            first_effects,
            first_payload,
        )];
        let (second_opportunity, expected_slot) = (2_u64..=256)
            .find_map(|sequence| {
                let opportunity = medium_opportunity("sender-b", sequence, &[2]);
                let slot = uniform_inclusive(
                    network_effect_draw(scenario_seed, &opportunity, &action, "medium-backoff", 1),
                    1,
                );
                (slot == 1).then_some((opportunity, slot))
            })
            .unwrap_or_else(|| panic!("test must find a nonzero keyed backoff"));
        let mut second_payload = vec![2];
        let mut second_effects = crucible::ResolvedNetworkFrameEffects::default();
        let second_release = apply_network_shared_medium(
            &mut second_payload,
            &mut second_effects,
            &mut state,
            &mut pending,
            &topology,
            &action,
            &second_opportunity,
            scenario_seed,
            &resources,
            &policy_id,
            1,
            Some(1_000_000_000),
        )
        .unwrap_or_else(|error| panic!("retried contention frame: {error}"))
        .unwrap_or_else(|| panic!("retried contention frame must defer"));
        assert_eq!(expected_slot, 1);
        assert_eq!(second_release, 108);
        assert!(!second_effects.is_dropped());
        assert!(
            !pending[0]
                .fault_continuation
                .resolved_frame_effects()
                .is_dropped()
        );

        for collision in [
            crucible::model::NetworkPolicyCollision::DropAll,
            crucible::model::NetworkPolicyCollision::Capture,
            crucible::model::NetworkPolicyCollision::UndetectedTransform,
        ] {
            let policy_id = id("terminal-medium-policy");
            let transform_id = id("collision-transform");
            let mut policy = medium_policy(
                crucible::model::NetworkPolicyArbitration::Contention,
                collision,
            );
            if let Some(contention) = policy.contention.as_mut() {
                contention.capture_threshold_millionths = (collision
                    == crucible::model::NetworkPolicyCollision::Capture)
                    .then_some(positive(1_500_000));
            }
            let additional =
                if collision == crucible::model::NetworkPolicyCollision::UndetectedTransform {
                    policy
                        .contention
                        .as_mut()
                        .unwrap_or_else(|| panic!("test contention policy must exist"))
                        .undetected_transform = Some(transform_id.clone());
                    vec![crucible::model::WorldNetworkPolicyArtifact {
                        id: transform_id,
                        semantic_version: 1,
                        artifact: crucible::model::NetworkPolicyArtifactKind::ByteTemplate {
                            bytes: vec![0xff],
                        },
                    }]
                } else {
                    Vec::new()
                };
            let topology = medium_topology(policy_id.clone(), policy, additional);
            let action = medium_action(resources.clone(), policy_id.clone(), 2);
            let first_opportunity = medium_opportunity("sender-a", 1, &[0x0f]);
            let mut first_payload = vec![0x0f];
            let mut first_effects = crucible::ResolvedNetworkFrameEffects::default();
            let mut state = NetworkEffectRuntimeState::default();
            let release = apply_network_shared_medium(
                &mut first_payload,
                &mut first_effects,
                &mut state,
                &mut [],
                &topology,
                &action,
                &first_opportunity,
                scenario_seed,
                &resources,
                &policy_id,
                1,
                Some(1_000_000_000),
            )
            .unwrap_or_else(|error| panic!("terminal first frame: {error}"))
            .unwrap_or_else(|| panic!("terminal first frame must defer"));
            let mut pending = vec![pending_medium_frame(
                &first_opportunity,
                release,
                first_effects,
                first_payload,
            )];
            let second_opportunity = medium_opportunity("sender-b", 2, &[0xf0]);
            let mut second_payload = vec![0xf0];
            let mut second_effects = crucible::ResolvedNetworkFrameEffects::default();
            apply_network_shared_medium(
                &mut second_payload,
                &mut second_effects,
                &mut state,
                &mut pending,
                &topology,
                &action,
                &second_opportunity,
                scenario_seed,
                &resources,
                &policy_id,
                2,
                Some(1_000_000_000),
            )
            .unwrap_or_else(|error| panic!("terminal second frame: {error}"));
            match collision {
                crucible::model::NetworkPolicyCollision::DropAll => {
                    assert!(second_effects.is_dropped());
                    assert!(
                        pending[0]
                            .fault_continuation
                            .resolved_frame_effects()
                            .is_dropped()
                    );
                }
                crucible::model::NetworkPolicyCollision::Capture => {
                    assert!(!second_effects.is_dropped());
                    assert!(
                        pending[0]
                            .fault_continuation
                            .resolved_frame_effects()
                            .is_dropped()
                    );
                }
                crucible::model::NetworkPolicyCollision::UndetectedTransform => {
                    assert_eq!(second_payload, vec![0x0f]);
                    assert_eq!(pending[0].payload, vec![0xf0]);
                }
            }
        }
    }

    fn ethernet_ipv4_frame(data: &[u8], flags_offset: u16) -> Vec<u8> {
        const ETHERNET_HEADER: usize = 14;
        const IPV4_HEADER: usize = 20;
        let total_length = u16::try_from(IPV4_HEADER + data.len())
            .unwrap_or_else(|error| panic!("test IPv4 packet length: {error}"));
        let mut frame = vec![0_u8; ETHERNET_HEADER + IPV4_HEADER];
        frame[0..6].copy_from_slice(&[0, 1, 2, 3, 4, 5]);
        frame[6..12].copy_from_slice(&[6, 7, 8, 9, 10, 11]);
        frame[12..14].copy_from_slice(&[0x08, 0x00]);
        frame[14] = 0x45;
        frame[16..18].copy_from_slice(&total_length.to_be_bytes());
        frame[18..20].copy_from_slice(&0x1234_u16.to_be_bytes());
        frame[20..22].copy_from_slice(&flags_offset.to_be_bytes());
        frame[22] = 64;
        frame[23] = 17;
        frame[26..30].copy_from_slice(&[192, 0, 2, 1]);
        frame[30..34].copy_from_slice(&[198, 51, 100, 2]);
        frame.extend_from_slice(data);
        frame
    }

    #[test]
    fn forwarding_mutations_use_selectors_canonical_recipients_and_hop_limits() {
        let selector = id("forwarding-selector");
        let mut topology = crucible::model::WorldFaultTopology::default();
        topology
            .network_policy_artifacts
            .push(crucible::model::WorldNetworkPolicyArtifact {
                id: selector.clone(),
                semantic_version: 1,
                artifact: crucible::model::NetworkPolicyArtifactKind::PacketSelector {
                    matches: vec![crucible::model::NetworkPolicyByteMatch {
                        offset_bytes: 0,
                        value: vec![0xaa],
                        mask: vec![0xff],
                    }],
                },
            });
        let recipients =
            crucible::model::ObjectIdSet::new(vec![id("receiver-b"), id("receiver-a")])
                .unwrap_or_else(|error| panic!("test recipients: {error}"));
        let flood = action_with_network_effect(NetworkEffectSpecification::ForwardingMutation {
            selector: selector.clone(),
            mutation: crucible::model::NetworkForwardingMutationKind::Flood { recipients },
        });
        let mut payload = vec![0xaa];
        let mut effects = crucible::ResolvedNetworkFrameEffects::default();
        let mut state = NetworkEffectRuntimeState::default();
        let application = apply_network_frame_actions(
            &mut payload,
            &mut effects,
            &[flood],
            &opportunity(1),
            ContentHash::from_bytes(b"forwarding"),
            &topology,
            &mut state,
            &mut Vec::new(),
            None,
            None,
        )
        .unwrap_or_else(|error| panic!("flood mutation: {error}"));
        assert_eq!(
            application.forwarding_recipients,
            Some(vec![id("receiver-a"), id("receiver-b")])
        );
        assert!(effects.is_dropped());

        let loop_action =
            action_with_network_effect(NetworkEffectSpecification::ForwardingMutation {
                selector,
                mutation: crucible::model::NetworkForwardingMutationKind::Loop {
                    next_hop: id("receiver-a"),
                    hop_limit: positive(1),
                },
            });
        let exhausted = FaultOpportunity::new(
            loop_action.target.clone(),
            crucible::model::FaultOperation::NetworkTraverse,
            FaultPhase::Resolve,
            FaultCoordinate {
                virtual_nanos: 0,
                retired_instructions: None,
            },
            2,
            Some(crucible::model::FaultDirection::AToB),
            OpportunityPayload::NetworkFrame {
                producer: id("sender"),
                destination: id("receiver"),
                producer_sequence: 2,
                protocol_expansion_path: Vec::new(),
                generated_response_depth: 0,
                generated_response_cause: None,
                forwarding_mutation_path: vec![ContentHash::from_bytes(b"prior-hop")],
                length_bytes: 1,
                payload_digest: ContentHash::from_bytes(&payload),
            },
        )
        .unwrap_or_else(|error| panic!("loop opportunity: {error}"));
        let mut effects = crucible::ResolvedNetworkFrameEffects::default();
        let application = apply_network_frame_actions(
            &mut payload,
            &mut effects,
            &[loop_action],
            &exhausted,
            ContentHash::from_bytes(b"forwarding"),
            &topology,
            &mut state,
            &mut Vec::new(),
            None,
            None,
        )
        .unwrap_or_else(|error| panic!("loop mutation: {error}"));
        assert_eq!(application.forwarding_recipients, Some(Vec::new()));
        assert!(effects.is_dropped());
    }

    #[test]
    fn firewall_and_connection_state_are_bounded_exhaustive_and_timed() {
        let selector = id("stateful-selector");
        let key = id("flow-key");
        let machine = id("flow-machine");
        let event = id("packet-event");
        let transition =
            |from: &str, to: &str, delay_nanos| crucible::model::NetworkPolicyTransition {
                from: id(from),
                event: event.clone(),
                to: id(to),
                delay_nanos,
                traffic_policy: crucible::model::NetworkInFlightPolicy::Preserve,
            };
        let mut topology = crucible::model::WorldFaultTopology::default();
        topology.network_policy_artifacts = vec![
            crucible::model::WorldNetworkPolicyArtifact {
                id: selector.clone(),
                semantic_version: 1,
                artifact: crucible::model::NetworkPolicyArtifactKind::PacketSelector {
                    matches: vec![crucible::model::NetworkPolicyByteMatch {
                        offset_bytes: 0,
                        value: vec![0xaa],
                        mask: vec![0xff],
                    }],
                },
            },
            crucible::model::WorldNetworkPolicyArtifact {
                id: key.clone(),
                semantic_version: 1,
                artifact: crucible::model::NetworkPolicyArtifactKind::PacketKey {
                    ranges: vec![
                        crucible::model::ByteRange::new(0, 1)
                            .unwrap_or_else(|error| panic!("test packet key: {error}")),
                    ],
                },
            },
            crucible::model::WorldNetworkPolicyArtifact {
                id: machine.clone(),
                semantic_version: 1,
                artifact: crucible::model::NetworkPolicyArtifactKind::StateMachine {
                    initial: id("cold"),
                    states: vec![id("cold"), id("warm")],
                    transitions: vec![
                        transition("cold", "warm", 10),
                        transition("warm", "warm", 10),
                    ],
                },
            },
        ];
        topology
            .network_policy_artifacts
            .sort_by(|left, right| left.id.cmp(&right.id));
        let firewall =
            action_with_network_effect(NetworkEffectSpecification::FirewallDisposition {
                action: crucible::model::NetworkFirewallAction::Drop,
                typed_reject: None,
                rule: selector,
                state_machine: machine.clone(),
                transition_event: event.clone(),
            });
        let mut payload = vec![0xaa];
        let mut effects = crucible::ResolvedNetworkFrameEffects::default();
        let mut state = NetworkEffectRuntimeState::default();
        let application = apply_network_frame_actions(
            &mut payload,
            &mut effects,
            &[firewall],
            &opportunity(10),
            ContentHash::from_bytes(b"stateful"),
            &topology,
            &mut state,
            &mut Vec::new(),
            None,
            None,
        )
        .unwrap_or_else(|error| panic!("firewall state: {error}"));
        assert!(effects.is_dropped());
        assert_eq!(application.next_wakeup_nanos, Some(10));
        assert_eq!(state.state_machines.len(), 1);

        let bound = crucible::model::BoundedCount::new(CountLimit::LargeStateEntries, 1)
            .unwrap_or_else(|error| panic!("test table bound: {error}"));
        let connection = action_with_network_effect(NetworkEffectSpecification::ConnectionState {
            kind: crucible::model::NetworkConnectionKind::Conntrack,
            table_bound: bound,
            flow_key: key,
            state_machine: machine,
            transition_event: event,
            overflow: crucible::model::NetworkConnectionOverflow::DropNewest,
        });
        let mut first = vec![0xaa];
        let mut effects = crucible::ResolvedNetworkFrameEffects::default();
        apply_network_frame_actions(
            &mut first,
            &mut effects,
            std::slice::from_ref(&connection),
            &opportunity(11),
            ContentHash::from_bytes(b"stateful"),
            &topology,
            &mut state,
            &mut Vec::new(),
            None,
            None,
        )
        .unwrap_or_else(|error| panic!("first connection: {error}"));
        assert!(!effects.is_dropped());
        let mut second = vec![0xbb];
        let mut effects = crucible::ResolvedNetworkFrameEffects::default();
        apply_network_frame_actions(
            &mut second,
            &mut effects,
            &[connection],
            &opportunity(12),
            ContentHash::from_bytes(b"stateful"),
            &topology,
            &mut state,
            &mut Vec::new(),
            None,
            None,
        )
        .unwrap_or_else(|error| panic!("overflow connection: {error}"));
        assert!(effects.is_dropped());
        assert_eq!(
            state
                .connection_tables
                .values()
                .map(BTreeMap::len)
                .sum::<usize>(),
            1
        );
    }

    #[test]
    fn mtu_expansion_returns_real_child_frames_before_queue_service() {
        let mut action = action();
        action.phase = FaultPhase::Admit;
        action.effect = Arc::new(
            EffectRequest::new(
                EFFECT_SEMANTIC_VERSION,
                EffectLifetime::Persistent,
                EffectSpecification::Network(NetworkEffectSpecification::Mtu {
                    mtu_bytes: positive(42),
                    oversize: crucible::model::NetworkOversizeDisposition::Fragment,
                    fragmentation_protocol: Some(
                        crucible::model::NetworkFragmentationProtocol::EthernetIpv4,
                    ),
                    typed_error: None,
                }),
            )
            .unwrap_or_else(|error| panic!("test MTU effect: {error}")),
        );
        let mut payload = ethernet_ipv4_frame(&(0_u8..40).collect::<Vec<_>>(), 0);
        let opportunity = FaultOpportunity::new(
            action.target.clone(),
            crucible::model::FaultOperation::NetworkTraverse,
            FaultPhase::Admit,
            FaultCoordinate {
                virtual_nanos: 0,
                retired_instructions: None,
            },
            1,
            Some(crucible::model::FaultDirection::AToB),
            OpportunityPayload::NetworkFrame {
                producer: id("sender"),
                destination: id("receiver"),
                producer_sequence: 1,
                protocol_expansion_path: Vec::new(),
                generated_response_depth: 0,
                generated_response_cause: None,
                forwarding_mutation_path: Vec::new(),
                length_bytes: u64::try_from(payload.len())
                    .unwrap_or_else(|error| panic!("test frame length: {error}")),
                payload_digest: ContentHash::from_bytes(&payload),
            },
        )
        .unwrap_or_else(|error| panic!("test MTU opportunity: {error}"));
        let mut effects = crucible::ResolvedNetworkFrameEffects::default();
        let mut state = NetworkEffectRuntimeState::default();
        let application = apply_network_frame_actions(
            &mut payload,
            &mut effects,
            std::slice::from_ref(&action),
            &opportunity,
            ContentHash::from_bytes(b"mtu-expansion"),
            &crucible::model::WorldFaultTopology::default(),
            &mut state,
            &mut Vec::new(),
            None,
            None,
        )
        .unwrap_or_else(|error| panic!("MTU expansion: {error}"));
        assert_eq!(application.expanded_payloads.len(), 5);
        assert!(
            application
                .expanded_payloads
                .iter()
                .all(|fragment| fragment.len() <= 42)
        );
        assert!(state.queues.is_empty());
    }

    #[test]
    fn detected_errors_execute_declared_retries_and_timed_link_reset() {
        let retry_count = |value| {
            crucible::model::BoundedCount::new(CountLimit::DuplicatesOrInstructionReplay, value)
                .unwrap_or_else(|error| panic!("test retry count: {error}"))
        };
        let retry = action_with_network_effect(NetworkEffectSpecification::DetectedFrameError {
            kind: crucible::model::DetectedFrameErrorKind::Crc,
            receiver_action: crucible::model::DetectedFrameErrorAction::Retry,
            retry_delay_nanos: Some(positive(10)),
            retry_limit: Some(retry_count(3)),
            retry_attempts: Some(retry_count(2)),
            retry_succeeds: Some(true),
            reset_nanos: None,
        });
        let opportunity = opportunity(1);
        let mut payload = vec![0_u8];
        let mut effects = crucible::ResolvedNetworkFrameEffects::default();
        let mut state = NetworkEffectRuntimeState::default();
        apply_network_frame_action(
            &mut payload,
            &mut effects,
            &retry,
            &opportunity,
            ContentHash::from_bytes(b"retry-seed"),
            &crucible::model::WorldFaultTopology::default(),
            &mut state,
        )
        .unwrap_or_else(|error| panic!("retry effect: {error}"));
        assert_eq!(effects.additional_delay_nanos(), 20);
        assert!(!effects.is_dropped());

        let reset = action_with_network_effect(NetworkEffectSpecification::DetectedFrameError {
            kind: crucible::model::DetectedFrameErrorKind::FecUncorrectable,
            receiver_action: crucible::model::DetectedFrameErrorAction::LinkReset,
            retry_delay_nanos: None,
            retry_limit: None,
            retry_attempts: None,
            retry_succeeds: None,
            reset_nanos: Some(positive(50)),
        });
        let mut effects = crucible::ResolvedNetworkFrameEffects::default();
        apply_network_frame_action(
            &mut payload,
            &mut effects,
            &reset,
            &opportunity,
            ContentHash::from_bytes(b"reset-seed"),
            &crucible::model::WorldFaultTopology::default(),
            &mut state,
        )
        .unwrap_or_else(|error| panic!("reset effect: {error}"));
        assert!(effects.is_dropped());
        assert_eq!(state.boundary.next_wakeup_nanos(0), Some(50));
        let mut during_reset = crucible::ResolvedNetworkFrameEffects::default();
        state
            .boundary
            .apply_frame(
                &reset.target,
                None,
                &crucible::model::WorldFaultTopology::default(),
                49,
                &mut during_reset,
            )
            .unwrap_or_else(|error| panic!("apply reset outage: {error}"));
        assert!(during_reset.is_dropped());
        let mut recovered = crucible::ResolvedNetworkFrameEffects::default();
        state
            .boundary
            .apply_frame(
                &reset.target,
                None,
                &crucible::model::WorldFaultTopology::default(),
                50,
                &mut recovered,
            )
            .unwrap_or_else(|error| panic!("apply recovered link: {error}"));
        assert!(!recovered.is_dropped());
    }

    #[test]
    fn rf_channel_uses_geometry_tables_and_exact_sinr_profile() {
        let probability = crucible::model::ProbabilityMillionths::new(0)
            .unwrap_or_else(|error| panic!("zero probability should be valid: {error}"));
        let integer_table = |input_unit: &str, output| crucible::model::NetworkPolicyIntegerTable {
            input_unit: id(input_unit),
            output_unit: id("ratio-millionths"),
            interpolation: crucible::model::NetworkPolicyInterpolation::Step,
            outside: crucible::model::NetworkPolicyOutsideRange::Clamp,
            points: vec![crucible::model::NetworkPolicyIntegerPoint { input: 0, output }],
        };
        let profile = crucible::model::NetworkPolicyRfProfile {
            minimum_sinr: 0,
            rate_bps: positive(8_000),
            loss: probability,
            corruption: probability,
            corruption_action: crucible::model::NetworkPolicyRfCorruption::Corrected,
            maximum_retries: 0,
            retry_delay_nanos: 0,
        };
        let mut topology = crucible::model::WorldFaultTopology::default();
        topology.network_policy_artifacts = vec![
            crucible::model::WorldNetworkPolicyArtifact {
                id: id("propagation"),
                semantic_version: 1,
                artifact: crucible::model::NetworkPolicyArtifactKind::RfPropagation(
                    crucible::model::NetworkPolicyRfPropagation {
                        path_gain_ratio: integer_table("millimetres", 500_000),
                        antenna_gain_ratio: integer_table("millidegrees", 1_000_000),
                        spatial_cell_mm: positive(1),
                        fading_bucket_nanos: positive(1),
                    },
                ),
            },
            crucible::model::WorldNetworkPolicyArtifact {
                id: id("transfer"),
                semantic_version: 1,
                artifact: crucible::model::NetworkPolicyArtifactKind::RfTransfer(
                    crucible::model::NetworkPolicyRfTransfer {
                        profiles: vec![profile],
                    },
                ),
            },
        ];
        let effect = EffectRequest::new(
            EFFECT_SEMANTIC_VERSION,
            EffectLifetime::Opportunity,
            EffectSpecification::Network(NetworkEffectSpecification::RfChannel {
                carrier_hz: positive(2_400_000_000),
                bandwidth_hz: positive(20_000_000),
                transmit_power_femtowatts: 100,
                receiver_noise_femtowatts: 10,
                propagation_fields: id("propagation"),
                sinr_transfer: id("transfer"),
            }),
        )
        .unwrap_or_else(|error| panic!("test RF effect should be valid: {error}"));
        let action = ResolvedBindingAction {
            kind: BindingActionKind::Apply,
            binding: id("rf-binding"),
            target: ResolvedFaultTarget::NetworkSegment {
                segment: id("network-test-segment"),
                direction: crucible::model::FaultDirection::AToB,
            },
            phase: FaultPhase::Resolve,
            effect: Arc::new(effect),
            mapping_output: Arc::new(ResolvedMappingOutput::ServiceProfile {
                service_profile: id("rf-inputs"),
                input_contracts: vec![
                    crucible::model::ServiceProfileInput {
                        role: id("distance"),
                        shape: crucible::model::SignalShape {
                            value_type: crucible::model::SignalValueType::U64,
                            unit: crucible::model::SignalUnit::Millimetres,
                            scale_decimal_exponent: 0,
                        },
                    },
                    crucible::model::ServiceProfileInput {
                        role: id("orientation"),
                        shape: crucible::model::SignalShape {
                            value_type: crucible::model::SignalValueType::I64,
                            unit: crucible::model::SignalUnit::Millidegrees,
                            scale_decimal_exponent: 0,
                        },
                    },
                    crucible::model::ServiceProfileInput {
                        role: id("interference"),
                        shape: crucible::model::SignalShape {
                            value_type: crucible::model::SignalValueType::U64,
                            unit: crucible::model::SignalUnit::Femtowatts,
                            scale_decimal_exponent: 0,
                        },
                    },
                    crucible::model::ServiceProfileInput {
                        role: id("fading"),
                        shape: crucible::model::SignalShape {
                            value_type: crucible::model::SignalValueType::U64,
                            unit: crucible::model::SignalUnit::PartsPerMillion,
                            scale_decimal_exponent: 0,
                        },
                    },
                ],
                inputs: vec![
                    crucible::model::SignalValue::U64(10),
                    crucible::model::SignalValue::I64(0),
                    crucible::model::SignalValue::U64(5),
                    crucible::model::SignalValue::U64(1_000_000),
                ],
            }),
            mapped_digest: ContentHash::from_bytes(b"rf-inputs"),
            transition_sequence: 1,
            opportunity: None,
            coordinate: FaultCoordinate {
                virtual_nanos: 0,
                retired_instructions: None,
            },
            cause: BindingActionCause::Signal,
        };
        let opportunity = FaultOpportunity::new(
            action.target.clone(),
            crucible::model::FaultOperation::NetworkTraverse,
            FaultPhase::Resolve,
            action.coordinate,
            1,
            Some(crucible::model::FaultDirection::AToB),
            OpportunityPayload::NetworkFrame {
                producer: id("sender"),
                destination: id("receiver"),
                producer_sequence: 1,
                protocol_expansion_path: Vec::new(),
                generated_response_depth: 0,
                generated_response_cause: None,
                forwarding_mutation_path: Vec::new(),
                length_bytes: 1,
                payload_digest: ContentHash::from_bytes(b"frame"),
            },
        )
        .unwrap_or_else(|error| panic!("test RF opportunity should be valid: {error}"));
        let mut payload = vec![0_u8];
        let mut effects = crucible::ResolvedNetworkFrameEffects::default();
        let mut state = NetworkEffectRuntimeState::default();
        apply_network_frame_action(
            &mut payload,
            &mut effects,
            &action,
            &opportunity,
            ContentHash::from_bytes(b"scenario"),
            &topology,
            &mut state,
        )
        .unwrap_or_else(|error| panic!("RF effect should execute: {error}"));
        assert_eq!(effects.serialization_rate_cap_bps(), Some(8_000));
        assert!(!effects.is_dropped());

        let always = crucible::model::ProbabilityMillionths::new(1_000_000)
            .unwrap_or_else(|error| panic!("certain probability: {error}"));
        let transfer = topology
            .network_policy_artifacts
            .iter_mut()
            .find(|artifact| artifact.id == id("transfer"))
            .unwrap_or_else(|| panic!("test transfer artifact"));
        let crucible::model::NetworkPolicyArtifactKind::RfTransfer(transfer) =
            &mut transfer.artifact
        else {
            panic!("test transfer type")
        };
        transfer.profiles[0].loss = always;
        transfer.profiles[0].maximum_retries = 2;
        transfer.profiles[0].retry_delay_nanos = 7;
        let mut effects = crucible::ResolvedNetworkFrameEffects::default();
        apply_network_frame_action(
            &mut payload,
            &mut effects,
            &action,
            &opportunity,
            ContentHash::from_bytes(b"scenario"),
            &topology,
            &mut state,
        )
        .unwrap_or_else(|error| panic!("RF retry exhaustion: {error}"));
        assert_eq!(effects.additional_delay_nanos(), 14);
        assert!(effects.is_dropped());

        topology
            .network_policy_artifacts
            .push(crucible::model::WorldNetworkPolicyArtifact {
                id: id("rf-xor"),
                semantic_version: 1,
                artifact: crucible::model::NetworkPolicyArtifactKind::ByteTemplate {
                    bytes: vec![0xff],
                },
            });
        topology
            .network_policy_artifacts
            .sort_by(|left, right| left.id.cmp(&right.id));
        let transfer = topology
            .network_policy_artifacts
            .iter_mut()
            .find(|artifact| artifact.id == id("transfer"))
            .unwrap_or_else(|| panic!("test transfer artifact"));
        let crucible::model::NetworkPolicyArtifactKind::RfTransfer(transfer) =
            &mut transfer.artifact
        else {
            panic!("test transfer type")
        };
        transfer.profiles[0].loss = probability;
        transfer.profiles[0].corruption = always;
        transfer.profiles[0].corruption_action =
            crucible::model::NetworkPolicyRfCorruption::Undetected {
                transform: id("rf-xor"),
            };
        transfer.profiles[0].maximum_retries = 0;
        let mut payload = vec![0x0f, 0xf0];
        let mut effects = crucible::ResolvedNetworkFrameEffects::default();
        apply_network_frame_action(
            &mut payload,
            &mut effects,
            &action,
            &opportunity,
            ContentHash::from_bytes(b"scenario"),
            &topology,
            &mut state,
        )
        .unwrap_or_else(|error| panic!("RF undetected corruption: {error}"));
        assert_eq!(payload, vec![0xf0, 0x0f]);
        assert!(!effects.is_dropped());
    }

    fn reservation(class: &str, sequence: u64, bytes: u64) -> NetworkQueueReservation {
        NetworkQueueReservation {
            enqueue_nanos: 0,
            base_ready_nanos: 0,
            ready_nanos: 0,
            service_start_nanos: 0,
            finish_nanos: 0,
            bytes,
            payload_bits: bytes * 8,
            remaining_nano_bits: u128::from(bytes) * 8 * 1_000_000_000,
            base_rate_bps: Some(1_000_000),
            service_curves: Vec::new(),
            class: Some(id(class)),
            opportunity: ContentHash::from_bytes(&sequence.to_be_bytes()),
        }
    }

    fn queue_parameters() -> crucible::model::NetworkPolicyQueueDiscipline {
        crucible::model::NetworkPolicyQueueDiscipline {
            classes: vec![
                crucible::model::NetworkPolicyQueueClass {
                    class: id("high"),
                    selector: id("high-selector"),
                    priority: 0,
                    weight: positive(3),
                    quantum_bytes: positive(1_500),
                },
                crucible::model::NetworkPolicyQueueClass {
                    class: id("low"),
                    selector: id("low-selector"),
                    priority: 10,
                    weight: positive(1),
                    quantum_bytes: positive(500),
                },
            ],
            red_minimum_bytes: None,
            red_maximum_bytes: None,
            red_maximum_probability: None,
            red_weight_numerator: None,
            red_weight_denominator: None,
        }
    }

    #[test]
    fn service_curve_integrates_across_rate_changes() {
        let curves = vec![NetworkServiceCurveState {
            activation_nanos: 0,
            segments: vec![
                crucible::model::NetworkServiceSegment {
                    at_nanos: 0,
                    rate_bps: positive(8),
                },
                crucible::model::NetworkServiceSegment {
                    at_nanos: 500_000_000,
                    rate_bps: positive(16),
                },
            ],
        }];
        let finish = network_service_finish(0, 8, None, &curves, &action())
            .unwrap_or_else(|error| panic!("service integration should succeed: {error}"));
        assert_eq!(finish, 750_000_000);
    }

    #[test]
    fn queue_reschedule_preserves_exact_partially_served_work() {
        let action = action();
        let mut queued = reservation("high", 1, 1);
        queued.base_rate_bps = Some(8);
        queued.service_start_nanos = 0;
        queued.finish_nanos = 1_000_000_000;
        let mut queue = NetworkQueueState {
            configuration: Some(NetworkQueueConfiguration {
                owner: NetworkEffectStateKey::from_action(&action),
                discipline: crucible::model::NetworkQueueDiscipline::Fifo,
                discipline_parameters: None,
            }),
            reservations: vec![queued],
            ..NetworkQueueState::default()
        };
        reschedule_network_queue(
            &mut queue,
            &mut [],
            &action,
            crucible::model::NetworkQueueDiscipline::Fifo,
            None,
            500_000_000,
            None,
        )
        .unwrap_or_else(|error| panic!("partial queue reschedule: {error}"));
        assert_eq!(queue.reservations[0].remaining_nano_bits, 4_000_000_000);
        assert_eq!(queue.reservations[0].service_start_nanos, 500_000_000);
        assert_eq!(queue.reservations[0].finish_nanos, 1_000_000_000);
    }

    #[test]
    fn class_backpressure_preempts_without_blocking_ready_siblings() {
        let owner = action();
        let parameters_id = id("queue-parameters");
        let mut topology = crucible::model::WorldFaultTopology::default();
        topology
            .network_policy_artifacts
            .push(crucible::model::WorldNetworkPolicyArtifact {
                id: parameters_id.clone(),
                semantic_version: 1,
                artifact: crucible::model::NetworkPolicyArtifactKind::QueueDiscipline(
                    queue_parameters(),
                ),
            });
        let mut high = reservation("high", 1, 1);
        high.finish_nanos = 8_000;
        let mut low = reservation("low", 2, 1);
        low.service_start_nanos = 8_000;
        low.finish_nanos = 16_000;
        let mut state = NetworkEffectRuntimeState::default();
        state.queues.insert(
            owner.target.clone(),
            NetworkQueueState {
                configuration: Some(NetworkQueueConfiguration {
                    owner: NetworkEffectStateKey::from_action(&owner),
                    discipline: crucible::model::NetworkQueueDiscipline::StrictPriority,
                    discipline_parameters: Some(parameters_id),
                }),
                reservations: vec![high, low],
                ..NetworkQueueState::default()
            },
        );
        let pause = action_with_network_effect(NetworkEffectSpecification::PauseBackpressure {
            class: id("high"),
            pause_nanos: Some(positive(100)),
        });
        let wakeup =
            apply_network_backpressure_transitions(&mut state, &mut [], &[pause], &topology, 0)
                .unwrap_or_else(|error| panic!("apply class pause: {error}"));
        assert_eq!(wakeup, Some(100));
        let queue = state
            .queues
            .get(&owner.target)
            .unwrap_or_else(|| panic!("test queue should remain"));
        assert_eq!(queue.reservations[0].class.as_ref(), Some(&id("low")));
        assert_eq!(queue.reservations[1].ready_nanos, 100);
    }

    #[test]
    fn token_bucket_preserves_ceil_surplus_without_rate_bias() {
        let action = action();
        let mut state = NetworkEffectRuntimeState::default();
        let mut release = 0;
        for sequence in 0..3 {
            release =
                apply_network_token_bucket(&mut state, &action, &opportunity(sequence), 1, 3, 8, 0)
                    .unwrap_or_else(|error| panic!("token service should succeed: {error}"));
        }
        assert_eq!(release, 8_000_000_000);
    }

    #[test]
    fn class_queue_comparators_use_priority_weight_and_quantum() {
        let parameters = queue_parameters();
        let high = reservation("high", 1, 1_500);
        let low = reservation("low", 2, 500);
        assert_eq!(
            compare_queue_candidates(
                &high,
                &low,
                crucible::model::NetworkQueueDiscipline::StrictPriority,
                Some(&parameters),
                &BTreeMap::new(),
                &BTreeMap::new(),
            ),
            std::cmp::Ordering::Less
        );

        let projected_frames = BTreeMap::from([(id("high"), 3), (id("low"), 0)]);
        assert_eq!(
            compare_queue_candidates(
                &low,
                &high,
                crucible::model::NetworkQueueDiscipline::WeightedRoundRobin,
                Some(&parameters),
                &projected_frames,
                &BTreeMap::new(),
            ),
            std::cmp::Ordering::Less
        );

        let projected_bytes = BTreeMap::from([(id("high"), 4_500), (id("low"), 0)]);
        assert_eq!(
            compare_queue_candidates(
                &low,
                &high,
                crucible::model::NetworkQueueDiscipline::DeficitRoundRobin,
                Some(&parameters),
                &BTreeMap::new(),
                &projected_bytes,
            ),
            std::cmp::Ordering::Less
        );
    }

    fn custody_topology(
        disposition: crucible::model::NetworkPolicyOverflow,
        contact_start: u64,
    ) -> crucible::model::WorldFaultTopology {
        let timeout_nanos = (disposition == crucible::model::NetworkPolicyOverflow::Timeout)
            .then_some(positive(25));
        let typed_error = (disposition == crucible::model::NetworkPolicyOverflow::TypedError)
            .then_some(id("custody-reject"));
        let mut artifacts = vec![
            crucible::model::WorldNetworkPolicyArtifact {
                id: id("contact-capacity"),
                semantic_version: 1,
                artifact: crucible::model::NetworkPolicyArtifactKind::ServiceCurve {
                    segments: crucible::model::NetworkServiceSegments::new(vec![
                        crucible::model::NetworkServiceSegment {
                            at_nanos: 0,
                            rate_bps: positive(8_000_000_000),
                        },
                    ])
                    .unwrap_or_else(|error| panic!("contact service curve: {error}")),
                },
            },
            crucible::model::WorldNetworkPolicyArtifact {
                id: id("contact-plan"),
                semantic_version: 1,
                artifact: crucible::model::NetworkPolicyArtifactKind::ContactPlan {
                    intervals: vec![crucible::model::NetworkPolicyContactInterval {
                        contact: id("contact-a"),
                        service_resource: id("resource-a"),
                        route_cost: positive(1),
                        routing_propagation_nanos: 1,
                        start_nanos: contact_start,
                        end_nanos: contact_start + 100,
                        source: id("sender"),
                        destination: id("receiver"),
                        beam: id("beam-a"),
                        gateway: id("gateway-a"),
                        minimum_range_mm: 1,
                        maximum_range_mm: 2,
                        capacity_profile: id("contact-capacity"),
                        acquisition_nanos: 10,
                        teardown_nanos: 10,
                        confidence: crucible::model::ProbabilityMillionths::new(1_000_000)
                            .unwrap_or_else(|error| panic!("contact confidence: {error}")),
                        provenance: id("contact-test"),
                    }],
                },
            },
            crucible::model::WorldNetworkPolicyArtifact {
                id: id("custody-policy"),
                semantic_version: 1,
                artifact: crucible::model::NetworkPolicyArtifactKind::Overflow {
                    disposition,
                    timeout_nanos,
                    typed_error,
                },
            },
        ];
        if disposition == crucible::model::NetworkPolicyOverflow::TypedError {
            artifacts.push(crucible::model::WorldNetworkPolicyArtifact {
                id: id("custody-reject"),
                semantic_version: 1,
                artifact: crucible::model::NetworkPolicyArtifactKind::TypedResponse(
                    crucible::model::NetworkPolicyTypedResponseSet {
                        responses: vec![crucible::model::NetworkPolicyTypedResponse {
                            response: crucible::model::NetworkPolicyTypedResponseKind::TcpReset,
                            headers: crucible::model::NetworkPolicyResponseHeaders {
                                source_mac: None,
                                source_ipv4: None,
                                source_ipv6: None,
                                hop_limit: 64,
                                ipv4_identification: 1,
                                delay_nanos: None,
                            },
                        }],
                        unmatched: crucible::model::NetworkPolicyUnmatchedResponse::Suppress,
                    },
                ),
            });
        }
        artifacts.sort_by(|left, right| left.id.cmp(&right.id));
        crucible::model::WorldFaultTopology {
            network_policy_artifacts: artifacts,
            ..crucible::model::WorldFaultTopology::default()
        }
    }

    fn custody_action() -> ResolvedBindingAction {
        action_with_network_effect(NetworkEffectSpecification::CustodyQueue {
            capacity_bytes: positive(1),
            capacity_bundles: crucible::model::BoundedCount::new(CountLimit::LargeStateEntries, 1)
                .unwrap_or_else(|error| panic!("custody bundle capacity: {error}")),
            expiry_nanos: positive(1_000),
            custody_policy: id("custody-policy"),
            route_contact_plan: id("contact-plan"),
            priority: crucible::model::NetworkBundlePriority::Normal,
            max_visited_hops: crucible::model::BoundedCount::new(
                CountLimit::DuplicatesOrInstructionReplay,
                8,
            )
            .unwrap_or_else(|error| panic!("custody hop bound: {error}")),
        })
    }

    fn opportunity_at(sequence: u64, now: u64) -> FaultOpportunity {
        let mut opportunity = opportunity(sequence);
        opportunity = FaultOpportunity::new(
            opportunity.target().clone(),
            opportunity.operation(),
            opportunity.phase(),
            FaultCoordinate {
                virtual_nanos: now,
                retired_instructions: None,
            },
            sequence,
            opportunity.direction(),
            opportunity.payload().clone(),
        )
        .unwrap_or_else(|error| panic!("coordinate-adjusted opportunity: {error}"));
        opportunity
    }

    fn pending_custody_frame(
        opportunity: &FaultOpportunity,
        release_nanos: u64,
    ) -> crucible::BackendNetworkOutput {
        let mut continuation = crucible::BackendNetworkFaultContinuation::default();
        continuation
            .cursor_mut()
            .defer_until(release_nanos, opportunity.id());
        let sequence = match opportunity.payload() {
            OpportunityPayload::NetworkFrame {
                producer_sequence, ..
            } => *producer_sequence,
            _ => panic!("test custody opportunity must be a frame"),
        };
        crucible::BackendNetworkOutput {
            source: crucible::NodeId {
                name: String::from("sender"),
            },
            destination: crucible::NodeId {
                name: String::from("logical-router"),
            },
            emit_icount: crucible::Icount { retired: 0 },
            sequence,
            payload: vec![u8::try_from(sequence).unwrap_or(0)],
            route: Some(crucible::BackendNetworkRoute {
                link: crucible::LinkId::from_name("custody-test-link"),
                direction: crucible::device::NetworkLinkDirection::EndpointAToEndpointB,
                destination: crucible::NodeId {
                    name: String::from("receiver"),
                },
            }),
            fault_continuation: continuation,
        }
    }

    #[test]
    fn custody_waits_for_contact_then_conserves_shared_capacity() {
        let topology = custody_topology(crucible::model::NetworkPolicyOverflow::DropNewest, 100);
        let action = custody_action();
        let mut state = NetworkEffectRuntimeState::default();
        let mut pending = Vec::new();
        let mut typed_response = None;
        let mut first_effects = crucible::ResolvedNetworkFrameEffects::default();
        let waiting = apply_network_custody_queue(
            &[1],
            &mut first_effects,
            &mut state,
            &mut pending,
            &topology,
            &action,
            &opportunity_at(1, 0),
            1,
            1,
            1_000,
            &id("custody-policy"),
            &id("contact-plan"),
            crucible::model::NetworkBundlePriority::Normal,
            8,
            &mut typed_response,
        )
        .unwrap_or_else(|error| panic!("queue before contact: {error}"));
        assert_eq!(waiting.defer_until, Some(110));
        assert!(waiting.repeat_phase_on_resume);

        let service = apply_network_custody_queue(
            &[1],
            &mut first_effects,
            &mut state,
            &mut pending,
            &topology,
            &action,
            &opportunity_at(1, 110),
            1,
            1,
            1_000,
            &id("custody-policy"),
            &id("contact-plan"),
            crucible::model::NetworkBundlePriority::Normal,
            8,
            &mut typed_response,
        )
        .unwrap_or_else(|error| panic!("reserve at contact: {error}"));
        assert_eq!(service.defer_until, Some(112));
        assert_eq!(first_effects.additional_delay_nanos(), 0);
        assert_eq!(first_effects.accounted_contact_services().len(), 1);
        let released = apply_network_custody_queue(
            &[1],
            &mut first_effects,
            &mut state,
            &mut pending,
            &topology,
            &action,
            &opportunity_at(1, 112),
            1,
            1,
            1_000,
            &id("custody-policy"),
            &id("contact-plan"),
            crucible::model::NetworkBundlePriority::Normal,
            8,
            &mut typed_response,
        )
        .unwrap_or_else(|error| panic!("release after propagation: {error}"));
        assert_eq!(released.defer_until, None);

        let mut second_effects = crucible::ResolvedNetworkFrameEffects::default();
        let second = apply_network_custody_queue(
            &[2],
            &mut second_effects,
            &mut state,
            &mut pending,
            &topology,
            &action,
            &opportunity_at(2, 112),
            1,
            1,
            1_000,
            &id("custody-policy"),
            &id("contact-plan"),
            crucible::model::NetworkBundlePriority::Normal,
            8,
            &mut typed_response,
        )
        .unwrap_or_else(|error| panic!("second contact reservation: {error}"));
        assert_eq!(second.defer_until, Some(114));
        apply_network_custody_queue(
            &[2],
            &mut second_effects,
            &mut state,
            &mut pending,
            &topology,
            &action,
            &opportunity_at(2, 114),
            1,
            1,
            1_000,
            &id("custody-policy"),
            &id("contact-plan"),
            crucible::model::NetworkBundlePriority::Normal,
            8,
            &mut typed_response,
        )
        .unwrap_or_else(|error| panic!("second contact release: {error}"));
        assert_eq!(second_effects.additional_delay_nanos(), 0);
        let queue = state
            .custody_queues
            .get(&NetworkEffectStateKey::from_action(&action))
            .unwrap_or_else(|| panic!("custody queue state"));
        assert_eq!(queue.released_bundles, 2);
        assert!(queue.reservations.is_empty());
    }

    #[test]
    fn custody_selects_and_reserves_a_bounded_multihop_contact_route() {
        let mut topology =
            custody_topology(crucible::model::NetworkPolicyOverflow::DropNewest, 100);
        let plan = topology
            .network_policy_artifacts
            .iter_mut()
            .find(|artifact| artifact.id == id("contact-plan"))
            .unwrap_or_else(|| panic!("contact plan"));
        let crucible::model::NetworkPolicyArtifactKind::ContactPlan { intervals } =
            &mut plan.artifact
        else {
            panic!("contact plan type")
        };
        let mut first = intervals[0].clone();
        first.contact = id("contact-a-relay");
        first.service_resource = id("radio-a-relay");
        first.destination = id("relay");
        first.route_cost = positive(1);
        let mut second = intervals[0].clone();
        second.contact = id("contact-b-receiver");
        second.service_resource = id("radio-b-receiver");
        second.start_nanos = 120;
        second.end_nanos = 220;
        second.source = id("relay");
        second.route_cost = positive(1);
        let mut direct = intervals[0].clone();
        direct.contact = id("contact-c-direct");
        direct.service_resource = id("radio-c-direct");
        direct.route_cost = positive(10);
        *intervals = vec![first, direct, second];

        let action = custody_action();
        let mut state = NetworkEffectRuntimeState::default();
        let mut effects = crucible::ResolvedNetworkFrameEffects::default();
        let mut response = None;
        let reserved = apply_network_custody_queue(
            &[1],
            &mut effects,
            &mut state,
            &mut Vec::new(),
            &topology,
            &action,
            &opportunity_at(1, 0),
            1,
            1,
            1_000,
            &id("custody-policy"),
            &id("contact-plan"),
            crucible::model::NetworkBundlePriority::Normal,
            8,
            &mut response,
        )
        .unwrap_or_else(|error| panic!("reserve multihop route: {error}"));
        assert_eq!(reserved.defer_until, Some(110));
        assert!(effects.accounted_contact_services().is_empty());
        assert!(state.contact_services.is_empty());
        let reserved = apply_network_custody_queue(
            &[1],
            &mut effects,
            &mut state,
            &mut Vec::new(),
            &topology,
            &action,
            &opportunity_at(1, 110),
            1,
            1,
            1_000,
            &id("custody-policy"),
            &id("contact-plan"),
            crucible::model::NetworkBundlePriority::Normal,
            8,
            &mut response,
        )
        .unwrap_or_else(|error| panic!("commit multihop route: {error}"));
        assert_eq!(reserved.defer_until, Some(132));
        assert_eq!(effects.accounted_contact_services().len(), 2);
        let queue = state
            .custody_queues
            .get(&NetworkEffectStateKey::from_action(&action))
            .unwrap_or_else(|| panic!("custody queue"));
        assert_eq!(
            queue.reservations[0].contact_path,
            vec![id("contact-a-relay"), id("contact-b-receiver")]
        );
        assert_eq!(state.contact_services.len(), 2);

        let contact = action_with_network_effect(NetworkEffectSpecification::Contact {
            intervals: id("contact-plan"),
            range_delay_lookup: id("direct-range-delay"),
            beams: crucible::model::ObjectIdSet::new(vec![id("beam-a")])
                .unwrap_or_else(|error| panic!("contact beams: {error}")),
            gateways: crucible::model::ObjectIdSet::new(vec![id("gateway-a")])
                .unwrap_or_else(|error| panic!("contact gateways: {error}")),
        });
        apply_network_frame_action(
            &mut vec![1],
            &mut effects,
            &contact,
            &opportunity_at(1, 132),
            ContentHash::from_bytes(b"multihop-contact-composition"),
            &topology,
            &mut state,
        )
        .unwrap_or_else(|error| panic!("compose multihop custody with contact: {error}"));
        assert!(!effects.is_dropped());
        assert_eq!(effects.additional_delay_nanos(), 0);
        assert_eq!(state.contact_services.len(), 2);
    }

    #[test]
    fn custody_checkpoint_rejects_broken_contact_graph_joins() {
        let topology = custody_topology(crucible::model::NetworkPolicyOverflow::DropNewest, 100);
        let action = custody_action();
        let owner = NetworkEffectStateKey::from_action(&action);
        let mut state = NetworkEffectRuntimeState::default();
        let mut effects = crucible::ResolvedNetworkFrameEffects::default();
        let mut response = None;
        let first = opportunity_at(1, 0);
        let waiting = apply_network_custody_queue(
            &[1],
            &mut effects,
            &mut state,
            &mut Vec::new(),
            &topology,
            &action,
            &first,
            1,
            1,
            1_000,
            &id("custody-policy"),
            &id("contact-plan"),
            crucible::model::NetworkBundlePriority::Normal,
            8,
            &mut response,
        )
        .unwrap_or_else(|error| panic!("stage custody route: {error}"));
        let service_opportunity = opportunity_at(
            1,
            waiting
                .defer_until
                .unwrap_or_else(|| panic!("custody route must wait for contact")),
        );
        let mut planned_pending = vec![pending_custody_frame(
            &first,
            service_opportunity.coordinate().virtual_nanos,
        )];
        planned_pending[0]
            .fault_continuation
            .cursor_mut()
            .defer_repeated_effect_until(
                service_opportunity.coordinate().virtual_nanos,
                first.id(),
                crucible::model::EffectKind::NetworkCustodyQueue,
                Some(crucible::model::NetworkBundlePriority::Normal.rank()),
            );
        validate_custody_contact_topology(&state, &planned_pending, &topology)
            .unwrap_or_else(|error| panic!("valid planned custody checkpoint: {error}"));
        let mut planned_extra = planned_pending.clone();
        let mut planned_effects = crucible::ResolvedNetworkFrameEffects::default();
        planned_effects
            .mark_contact_service_accounted([0x6b; 32])
            .unwrap_or_else(|error| panic!("planned extra contact: {error}"));
        planned_extra[0]
            .fault_continuation
            .set_resolved_frame_effects(planned_effects);
        assert!(validate_custody_contact_topology(&state, &planned_extra, &topology).is_err());
        let committed = apply_network_custody_queue(
            &[1],
            &mut effects,
            &mut state,
            &mut Vec::new(),
            &topology,
            &action,
            &service_opportunity,
            1,
            1,
            1_000,
            &id("custody-policy"),
            &id("contact-plan"),
            crucible::model::NetworkBundlePriority::Normal,
            8,
            &mut response,
        )
        .unwrap_or_else(|error| panic!("commit custody route: {error}"));
        let release = committed
            .defer_until
            .unwrap_or_else(|| panic!("committed custody route must have a release"));
        let mut pending = vec![pending_custody_frame(&service_opportunity, release)];
        pending[0]
            .fault_continuation
            .cursor_mut()
            .defer_repeated_effect_until(
                release,
                service_opportunity.id(),
                crucible::model::EffectKind::NetworkCustodyQueue,
                Some(crucible::model::NetworkBundlePriority::Normal.rank()),
            );
        pending[0]
            .fault_continuation
            .set_resolved_frame_effects(effects);
        validate_custody_contact_topology(&state, &pending, &topology)
            .unwrap_or_else(|error| panic!("valid custody checkpoint join: {error}"));

        let mut mismatched_output = pending.clone();
        mismatched_output[0].payload.push(2);
        assert!(validate_custody_contact_topology(&state, &mismatched_output, &topology).is_err());

        let mut mismatched_priority = state.clone();
        mismatched_priority
            .custody_queues
            .get_mut(&owner)
            .unwrap_or_else(|| panic!("custody queue"))
            .reservations[0]
            .bundle
            .priority = crucible::model::NetworkBundlePriority::Bulk;
        assert!(
            validate_custody_contact_topology(&mismatched_priority, &pending, &topology).is_err()
        );

        let mut mismatched_bytes = state.clone();
        mismatched_bytes
            .contact_services
            .values_mut()
            .next()
            .unwrap_or_else(|| panic!("contact service"))
            .reservations[0]
            .bytes = 2;
        assert!(validate_custody_contact_topology(&mismatched_bytes, &pending, &topology).is_err());

        let mut orphaned_ledger = state.clone();
        orphaned_ledger
            .contact_services
            .values_mut()
            .next()
            .unwrap_or_else(|| panic!("contact service"))
            .reservations[0]
            .custody_owner = Some(NetworkEffectStateKey {
            binding: id("missing-custody-binding"),
            target: action.target.clone(),
            effect: crucible::model::EffectKind::NetworkCustodyQueue,
        });
        assert!(validate_custody_contact_topology(&orphaned_ledger, &pending, &topology).is_err());

        let mut overlapping_ledger = state.clone();
        let service = overlapping_ledger
            .contact_services
            .values_mut()
            .next()
            .unwrap_or_else(|| panic!("contact service"));
        let mut duplicate = service.reservations[0].clone();
        duplicate.opportunity = ContentHash::from_bytes(b"overlapping-contact-reservation");
        service.served_bundles += 1;
        service.served_bytes += duplicate.bytes;
        service.reservations.push(duplicate);
        service.reservations.sort_by(|left, right| {
            (left.start_nanos, left.finish_nanos, left.opportunity).cmp(&(
                right.start_nanos,
                right.finish_nanos,
                right.opportunity,
            ))
        });
        assert!(
            validate_network_adapter_checkpoint(&NetworkAdapterCheckpoint {
                semantic_version: NETWORK_ADAPTER_CHECKPOINT_VERSION,
                coordinate: Some(release),
                coordinate_sequence: 0,
                effect_state: overlapping_ledger,
            })
            .is_err()
        );

        let mut mismatched_expiry = state.clone();
        mismatched_expiry
            .custody_queues
            .get_mut(&owner)
            .unwrap_or_else(|| panic!("custody queue"))
            .reservations[0]
            .expiry_nanos += 1;
        assert!(
            validate_network_adapter_checkpoint(&NetworkAdapterCheckpoint {
                semantic_version: NETWORK_ADAPTER_CHECKPOINT_VERSION,
                coordinate: Some(release),
                coordinate_sequence: 0,
                effect_state: mismatched_expiry,
            })
            .is_err()
        );

        let mut over_byte_capacity = state.clone();
        let reservation = &mut over_byte_capacity
            .custody_queues
            .get_mut(&owner)
            .unwrap_or_else(|| panic!("custody queue"))
            .reservations[0];
        reservation.bytes = 2;
        reservation.bundle.length_bytes = 2;
        assert!(
            validate_network_adapter_checkpoint(&NetworkAdapterCheckpoint {
                semantic_version: NETWORK_ADAPTER_CHECKPOINT_VERSION,
                coordinate: Some(release),
                coordinate_sequence: 0,
                effect_state: over_byte_capacity,
            })
            .is_err()
        );

        let mut over_bundle_capacity = state.clone();
        let queue = over_bundle_capacity
            .custody_queues
            .get_mut(&owner)
            .unwrap_or_else(|| panic!("custody queue"));
        let mut second = queue.reservations[0].clone();
        second.bundle.producer_sequence = 2;
        second.bundle.payload_digest = ContentHash::from_bytes(&[2]);
        second.opportunity = ContentHash::from_bytes(b"second-capacity-bundle");
        second.enqueue_nanos = 1;
        second.expiry_nanos = 1_001;
        queue.reservations.push(second);
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
        assert!(
            validate_network_adapter_checkpoint(&NetworkAdapterCheckpoint {
                semantic_version: NETWORK_ADAPTER_CHECKPOINT_VERSION,
                coordinate: Some(release),
                coordinate_sequence: 0,
                effect_state: over_bundle_capacity,
            })
            .is_err()
        );

        let mut missing_contact = state.clone();
        missing_contact
            .custody_queues
            .get_mut(&owner)
            .unwrap_or_else(|| panic!("custody queue"))
            .reservations[0]
            .contact_path[0] = id("missing-contact");
        assert!(validate_custody_contact_topology(&missing_contact, &pending, &topology).is_err());

        let mut missing_frame_accounting = pending.clone();
        let mut stripped_effects = missing_frame_accounting[0]
            .fault_continuation
            .resolved_frame_effects()
            .clone();
        stripped_effects.require_serialization();
        missing_frame_accounting[0]
            .fault_continuation
            .set_resolved_frame_effects(stripped_effects);
        assert!(
            validate_custody_contact_topology(&state, &missing_frame_accounting, &topology,)
                .is_err()
        );

        let mut extra_frame_accounting = pending.clone();
        let mut extra_effects = extra_frame_accounting[0]
            .fault_continuation
            .resolved_frame_effects()
            .clone();
        extra_effects
            .mark_contact_service_accounted([0x5a; 32])
            .unwrap_or_else(|error| panic!("extra contact accounting: {error}"));
        extra_frame_accounting[0]
            .fault_continuation
            .set_resolved_frame_effects(extra_effects);
        assert!(
            validate_custody_contact_topology(&state, &extra_frame_accounting, &topology,).is_err()
        );

        let mut missing_priority = pending.clone();
        missing_priority[0]
            .fault_continuation
            .cursor_mut()
            .defer_repeated_effect_until(
                release,
                service_opportunity.id(),
                crucible::model::EffectKind::NetworkCustodyQueue,
                None,
            );
        assert!(validate_custody_contact_topology(&state, &missing_priority, &topology).is_err());

        let mut mismatched_cursor = pending.clone();
        mismatched_cursor[0]
            .fault_continuation
            .cursor_mut()
            .defer_repeated_effect_until(
                release + 1,
                service_opportunity.id(),
                crucible::model::EffectKind::NetworkCustodyQueue,
                Some(crucible::model::NetworkBundlePriority::Normal.rank()),
            );
        assert!(validate_custody_contact_topology(&state, &mismatched_cursor, &topology).is_err());

        let mut mismatched_release = state.clone();
        let reservation = &mut mismatched_release
            .custody_queues
            .get_mut(&owner)
            .unwrap_or_else(|| panic!("custody queue"))
            .reservations[0];
        reservation.release_nanos = reservation.release_nanos.saturating_add(1);
        assert!(
            validate_custody_contact_topology(&mismatched_release, &pending, &topology,).is_err()
        );

        let mut service_before_enqueue = state.clone();
        let reservation = &mut service_before_enqueue
            .custody_queues
            .get_mut(&owner)
            .unwrap_or_else(|| panic!("custody queue"))
            .reservations[0];
        reservation.enqueue_nanos = 111;
        reservation.expiry_nanos = 1_111;
        assert!(
            validate_custody_contact_topology(&service_before_enqueue, &pending, &topology)
                .is_err()
        );
    }

    #[test]
    fn completed_contact_ledgers_fold_into_the_settled_cursor() {
        let key = NetworkContactServiceKey {
            plan: id("contact-plan"),
            contact: id("contact-a"),
            service_resource: id("resource-a"),
            source: id("sender"),
            destination: id("receiver"),
            start_nanos: 100,
            end_nanos: 200,
        };
        let mut state = NetworkEffectRuntimeState::default();
        state.contact_services.insert(
            key,
            NetworkContactServiceState {
                settled_cursor_nanos: 100,
                service_cursor_nanos: 112,
                served_bundles: 1,
                served_bytes: 1,
                reservations: vec![NetworkContactServiceReservation {
                    custody_owner: None,
                    opportunity: ContentHash::from_bytes(b"settled-contact"),
                    start_nanos: 110,
                    finish_nanos: 112,
                    arrival_nanos: 112,
                    bytes: 1,
                }],
            },
        );

        prune_network_contact_services(&mut state, 112);
        let service = state
            .contact_services
            .values()
            .next()
            .unwrap_or_else(|| panic!("contact service"));
        assert!(service.reservations.is_empty());
        assert_eq!(service.settled_cursor_nanos, 112);
        assert_eq!(service.service_cursor_nanos, 112);
        assert_eq!(service.served_bundles, 1);
        assert_eq!(service.served_bytes, 1);
    }

    #[test]
    fn direct_contact_counter_overflow_fails_before_mutation() {
        assert!(network_contact_service_state_capacity_allows(
            HARD_CONTACT_SERVICE_STATES - 1,
            1,
        ));
        assert!(!network_contact_service_state_capacity_allows(
            HARD_CONTACT_SERVICE_STATES,
            1,
        ));
        let topology = custody_topology(crucible::model::NetworkPolicyOverflow::DropNewest, 100);
        let plan = topology
            .network_policy_artifact(&id("contact-plan"))
            .unwrap_or_else(|| panic!("contact plan"));
        let crucible::model::NetworkPolicyArtifactKind::ContactPlan { intervals } = &plan.artifact
        else {
            panic!("contact plan type")
        };
        let interval = intervals[0].clone();
        let action = custody_action();
        for (served_bundles, served_bytes) in [(u64::MAX, 0), (0, u64::MAX)] {
            let key = NetworkContactServiceKey {
                plan: id("contact-plan"),
                contact: interval.contact.clone(),
                service_resource: interval.service_resource.clone(),
                source: interval.source.clone(),
                destination: interval.destination.clone(),
                start_nanos: interval.start_nanos,
                end_nanos: interval.end_nanos,
            };
            let mut state = NetworkEffectRuntimeState::default();
            state.contact_services.insert(
                key.clone(),
                NetworkContactServiceState {
                    settled_cursor_nanos: 100,
                    service_cursor_nanos: 100,
                    served_bundles,
                    served_bytes,
                    reservations: Vec::new(),
                },
            );
            let error = reserve_network_contact_service(
                &mut state,
                &topology,
                &id("contact-plan"),
                &interval,
                &id("sender"),
                &id("receiver"),
                110,
                1,
                ContentHash::from_bytes(b"overflow-direct-contact"),
                &action,
            )
            .expect_err("direct contact counter overflow must fail");
            assert!(error.to_string().contains("before direct reservation"));
            let service = state
                .contact_services
                .get(&key)
                .unwrap_or_else(|| panic!("contact service"));
            assert_eq!(service.service_cursor_nanos, 100);
            assert_eq!(service.served_bundles, served_bundles);
            assert_eq!(service.served_bytes, served_bytes);
            assert!(service.reservations.is_empty());
        }
    }

    #[test]
    fn custody_accounting_skips_direct_contact_propagation_and_revalidation() {
        let topology = custody_topology(crucible::model::NetworkPolicyOverflow::DropNewest, 100);
        let action = action_with_network_effect(NetworkEffectSpecification::Contact {
            intervals: id("contact-plan"),
            range_delay_lookup: id("direct-range-delay"),
            beams: crucible::model::ObjectIdSet::new(vec![id("beam-a")])
                .unwrap_or_else(|error| panic!("contact beams: {error}")),
            gateways: crucible::model::ObjectIdSet::new(vec![id("gateway-a")])
                .unwrap_or_else(|error| panic!("contact gateways: {error}")),
        });
        let key = NetworkContactServiceKey {
            plan: id("contact-plan"),
            contact: id("contact-a"),
            service_resource: id("resource-a"),
            source: id("sender"),
            destination: id("receiver"),
            start_nanos: 100,
            end_nanos: 200,
        };
        let mut effects = crucible::ResolvedNetworkFrameEffects::default();
        effects
            .mark_contact_service_accounted(network_contact_service_identity(&key))
            .unwrap_or_else(|error| panic!("account custody contact: {error}"));

        apply_network_frame_action(
            &mut vec![1],
            &mut effects,
            &action,
            &opportunity_at(1, 250),
            ContentHash::from_bytes(b"accounted-contact"),
            &topology,
            &mut NetworkEffectRuntimeState::default(),
        )
        .unwrap_or_else(|error| panic!("skip direct contact after custody: {error}"));
        assert!(!effects.is_dropped());
        assert_eq!(effects.additional_delay_nanos(), 0);
    }

    #[test]
    fn custody_priority_arbitrates_equal_contact_release_coordinates() {
        let topology = custody_topology(crucible::model::NetworkPolicyOverflow::DropNewest, 100);
        let bulk = custody_action();
        let mut critical = custody_action();
        critical.binding = id("critical-custody-binding");
        let mut state = NetworkEffectRuntimeState::default();
        let mut response = None;
        let mut bulk_effects = crucible::ResolvedNetworkFrameEffects::default();
        let mut critical_effects = crucible::ResolvedNetworkFrameEffects::default();
        for (sequence, action, priority, effects) in [
            (
                1,
                &bulk,
                crucible::model::NetworkBundlePriority::Bulk,
                &mut bulk_effects,
            ),
            (
                2,
                &critical,
                crucible::model::NetworkBundlePriority::Critical,
                &mut critical_effects,
            ),
        ] {
            let waiting = apply_network_custody_queue(
                &[u8::try_from(sequence).unwrap_or(0)],
                effects,
                &mut state,
                &mut Vec::new(),
                &topology,
                action,
                &opportunity_at(sequence, 0),
                1,
                1,
                1_000,
                &id("custody-policy"),
                &id("contact-plan"),
                priority,
                8,
                &mut response,
            )
            .unwrap_or_else(|error| panic!("stage priority bundle: {error}"));
            assert_eq!(waiting.defer_until, Some(110));
        }
        let critical_service = apply_network_custody_queue(
            &[2],
            &mut critical_effects,
            &mut state,
            &mut Vec::new(),
            &topology,
            &critical,
            &opportunity_at(2, 110),
            1,
            1,
            1_000,
            &id("custody-policy"),
            &id("contact-plan"),
            crucible::model::NetworkBundlePriority::Critical,
            8,
            &mut response,
        )
        .unwrap_or_else(|error| panic!("serve critical bundle: {error}"));
        let bulk_service = apply_network_custody_queue(
            &[1],
            &mut bulk_effects,
            &mut state,
            &mut Vec::new(),
            &topology,
            &bulk,
            &opportunity_at(1, 110),
            1,
            1,
            1_000,
            &id("custody-policy"),
            &id("contact-plan"),
            crucible::model::NetworkBundlePriority::Bulk,
            8,
            &mut response,
        )
        .unwrap_or_else(|error| panic!("serve bulk bundle: {error}"));
        assert_eq!(critical_service.defer_until, Some(112));
        assert_eq!(bulk_service.defer_until, Some(113));
    }

    #[test]
    fn custody_expiry_precedes_an_unreachable_future_contact() {
        let topology = custody_topology(crucible::model::NetworkPolicyOverflow::DropNewest, 2_000);
        let action = custody_action();
        let mut state = NetworkEffectRuntimeState::default();
        let mut effects = crucible::ResolvedNetworkFrameEffects::default();
        let mut typed_response = None;
        let waiting = apply_network_custody_queue(
            &[1],
            &mut effects,
            &mut state,
            &mut Vec::new(),
            &topology,
            &action,
            &opportunity_at(1, 0),
            1,
            1,
            1_000,
            &id("custody-policy"),
            &id("contact-plan"),
            crucible::model::NetworkBundlePriority::Normal,
            8,
            &mut typed_response,
        )
        .unwrap_or_else(|error| panic!("queue until expiry: {error}"));
        assert_eq!(waiting.defer_until, Some(1_000));
        apply_network_custody_queue(
            &[1],
            &mut effects,
            &mut state,
            &mut Vec::new(),
            &topology,
            &action,
            &opportunity_at(1, 1_000),
            1,
            1,
            1_000,
            &id("custody-policy"),
            &id("contact-plan"),
            crucible::model::NetworkBundlePriority::Normal,
            8,
            &mut typed_response,
        )
        .unwrap_or_else(|error| panic!("expire custody bundle: {error}"));
        assert!(effects.is_dropped());
    }

    #[test]
    fn custody_overflow_executes_every_closed_disposition() {
        for disposition in [
            crucible::model::NetworkPolicyOverflow::DropNewest,
            crucible::model::NetworkPolicyOverflow::DropOldest,
            crucible::model::NetworkPolicyOverflow::TypedError,
            crucible::model::NetworkPolicyOverflow::Timeout,
        ] {
            let topology = custody_topology(disposition, 500);
            let action = custody_action();
            let mut state = NetworkEffectRuntimeState::default();
            let first = opportunity_at(1, 0);
            let mut pending = Vec::new();
            let mut first_effects = crucible::ResolvedNetworkFrameEffects::default();
            let mut response = None;
            let first_application = apply_network_custody_queue(
                &[1],
                &mut first_effects,
                &mut state,
                &mut pending,
                &topology,
                &action,
                &first,
                1,
                1,
                1_000,
                &id("custody-policy"),
                &id("contact-plan"),
                crucible::model::NetworkBundlePriority::Normal,
                8,
                &mut response,
            )
            .unwrap_or_else(|error| panic!("first custody admission: {error}"));
            let first_release = first_application
                .defer_until
                .unwrap_or_else(|| panic!("first bundle must wait"));
            pending.push(pending_custody_frame(&first, first_release));

            let second = opportunity_at(2, 1);
            let mut second_effects = crucible::ResolvedNetworkFrameEffects::default();
            let second_application = apply_network_custody_queue(
                &[2],
                &mut second_effects,
                &mut state,
                &mut pending,
                &topology,
                &action,
                &second,
                1,
                1,
                1_000,
                &id("custody-policy"),
                &id("contact-plan"),
                crucible::model::NetworkBundlePriority::Normal,
                8,
                &mut response,
            )
            .unwrap_or_else(|error| panic!("custody overflow: {error}"));
            match disposition {
                crucible::model::NetworkPolicyOverflow::DropNewest => {
                    assert!(second_effects.is_dropped());
                    assert_eq!(pending.len(), 1);
                }
                crucible::model::NetworkPolicyOverflow::DropOldest => {
                    assert!(!second_effects.is_dropped());
                    assert!(second_application.repeat_phase_on_resume);
                    assert!(pending.is_empty());
                    let queue = state
                        .custody_queues
                        .get(&NetworkEffectStateKey::from_action(&action))
                        .unwrap_or_else(|| panic!("custody queue"));
                    assert_eq!(queue.reservations[0].bundle.producer_sequence, 2);
                }
                crucible::model::NetworkPolicyOverflow::TypedError => {
                    assert!(second_effects.is_dropped());
                    assert_eq!(response, Some(id("custody-reject")));
                }
                crucible::model::NetworkPolicyOverflow::Timeout => {
                    assert_eq!(second_application.defer_until, Some(26));
                    let mut timed_out = crucible::ResolvedNetworkFrameEffects::default();
                    apply_network_custody_queue(
                        &[2],
                        &mut timed_out,
                        &mut state,
                        &mut pending,
                        &topology,
                        &action,
                        &opportunity_at(2, 26),
                        1,
                        1,
                        1_000,
                        &id("custody-policy"),
                        &id("contact-plan"),
                        crucible::model::NetworkBundlePriority::Normal,
                        8,
                        &mut response,
                    )
                    .unwrap_or_else(|error| panic!("custody overflow timeout: {error}"));
                    assert!(timed_out.is_dropped());
                }
            }
        }
    }

    #[test]
    fn custody_removal_releases_the_real_pending_frame_at_the_boundary() {
        let topology = custody_topology(crucible::model::NetworkPolicyOverflow::DropNewest, 500);
        let action = custody_action();
        let first = opportunity_at(1, 0);
        let mut state = NetworkEffectRuntimeState::default();
        let mut effects = crucible::ResolvedNetworkFrameEffects::default();
        let mut response = None;
        let waiting = apply_network_custody_queue(
            &[1],
            &mut effects,
            &mut state,
            &mut Vec::new(),
            &topology,
            &action,
            &first,
            1,
            1,
            1_000,
            &id("custody-policy"),
            &id("contact-plan"),
            crucible::model::NetworkBundlePriority::Normal,
            8,
            &mut response,
        )
        .unwrap_or_else(|error| panic!("queue custody frame: {error}"));
        let release = waiting
            .defer_until
            .unwrap_or_else(|| panic!("custody frame must be pending"));
        assert_eq!(release, 510);
        let service_opportunity = opportunity_at(1, release);
        let service = apply_network_custody_queue(
            &[1],
            &mut effects,
            &mut state,
            &mut Vec::new(),
            &topology,
            &action,
            &service_opportunity,
            1,
            1,
            1_000,
            &id("custody-policy"),
            &id("contact-plan"),
            crucible::model::NetworkBundlePriority::Normal,
            8,
            &mut response,
        )
        .unwrap_or_else(|error| panic!("commit custody contact: {error}"));
        let service_release = service
            .defer_until
            .unwrap_or_else(|| panic!("committed custody frame must be pending"));
        let mut pending = vec![pending_custody_frame(&first, service_release)];
        pending[0]
            .fault_continuation
            .cursor_mut()
            .defer_repeated_effect_until(
                service_release,
                service_opportunity.id(),
                crucible::model::EffectKind::NetworkCustodyQueue,
                Some(crucible::model::NetworkBundlePriority::Normal.rank()),
            );
        pending[0]
            .fault_continuation
            .set_resolved_frame_effects(effects);
        let mut removal = action;
        removal.kind = BindingActionKind::RemovePersistent;
        removal.coordinate.virtual_nanos = 510;
        assert!(
            apply_network_custody_removals(&mut state, &mut pending, &[removal], 510)
                .unwrap_or_else(|error| panic!("remove custody binding: {error}"))
        );
        assert!(state.custody_queues.is_empty());
        assert!(
            state
                .contact_services
                .values()
                .all(|service| service.reservations.is_empty() && service.served_bundles == 0)
        );
        assert_eq!(
            pending[0].fault_continuation.cursor().not_before_nanos(),
            510
        );
        assert!(
            pending[0]
                .fault_continuation
                .resolved_frame_effects()
                .accounted_contact_services()
                .is_empty()
        );
        assert!(
            !pending[0]
                .fault_continuation
                .resolved_frame_effects()
                .serialization_is_accounted()
        );
    }

    #[test]
    fn simultaneous_custody_queues_fail_before_state_mutation() {
        let topology = custody_topology(crucible::model::NetworkPolicyOverflow::DropNewest, 100);
        let first = custody_action();
        let mut second = custody_action();
        second.binding = id("second-custody-binding");
        let mut payload = vec![1];
        let mut effects = crucible::ResolvedNetworkFrameEffects::default();
        let mut state = NetworkEffectRuntimeState::default();
        let error = apply_network_frame_actions(
            &mut payload,
            &mut effects,
            &[first, second],
            &opportunity_at(1, 0),
            ContentHash::from_bytes(b"custody-conflict"),
            &topology,
            &mut state,
            &mut Vec::new(),
            None,
            None,
        )
        .expect_err("two custody queues must conflict");
        assert!(error.to_string().contains("multiple custody queues"));
        assert!(state.custody_queues.is_empty());
        assert!(state.contact_services.is_empty());
    }

    #[test]
    fn custody_resume_does_not_charge_other_queue_effects_twice() {
        let topology = custody_topology(crucible::model::NetworkPolicyOverflow::DropNewest, 100);
        let token = action_with_network_effect(NetworkEffectSpecification::TokenBucket {
            rate_bps: positive(8),
            burst_bits: positive(16),
            initial_bits: 16,
        });
        let custody = custody_action();
        let actions = vec![token, custody];
        let mut payload = vec![1];
        let mut effects = crucible::ResolvedNetworkFrameEffects::default();
        let mut state = NetworkEffectRuntimeState::default();
        let first = apply_network_frame_actions(
            &mut payload,
            &mut effects,
            &actions,
            &opportunity_at(1, 0),
            ContentHash::from_bytes(b"custody-repeat"),
            &topology,
            &mut state,
            &mut Vec::new(),
            None,
            None,
        )
        .unwrap_or_else(|error| panic!("first queue evaluation: {error}"));
        assert_eq!(
            first.repeat_effect_on_resume,
            Some(crucible::model::EffectKind::NetworkCustodyQueue)
        );
        let token_state = state
            .token_buckets
            .values()
            .next()
            .map(|bucket| {
                (
                    bucket.tokens_nano_bits,
                    bucket.last_refill_nanos,
                    bucket.transition_sequence,
                )
            })
            .unwrap_or_else(|| panic!("token bucket state"));
        let release = first
            .defer_until
            .unwrap_or_else(|| panic!("custody release"));
        let resumed = apply_network_frame_actions(
            &mut payload,
            &mut effects,
            &actions,
            &opportunity_at(1, release),
            ContentHash::from_bytes(b"custody-repeat"),
            &topology,
            &mut state,
            &mut Vec::new(),
            None,
            Some(crucible::model::EffectKind::NetworkCustodyQueue),
        )
        .unwrap_or_else(|error| panic!("custody resume: {error}"));
        assert_eq!(
            resumed.repeat_effect_on_resume,
            Some(crucible::model::EffectKind::NetworkCustodyQueue)
        );
        let final_release = resumed
            .defer_until
            .unwrap_or_else(|| panic!("committed custody release"));
        let finalized = apply_network_frame_actions(
            &mut payload,
            &mut effects,
            &actions,
            &opportunity_at(1, final_release),
            ContentHash::from_bytes(b"custody-repeat"),
            &topology,
            &mut state,
            &mut Vec::new(),
            None,
            Some(crucible::model::EffectKind::NetworkCustodyQueue),
        )
        .unwrap_or_else(|error| panic!("custody finalize: {error}"));
        assert_eq!(finalized.repeat_effect_on_resume, None);
        let resumed_token_state = state
            .token_buckets
            .values()
            .next()
            .map(|bucket| {
                (
                    bucket.tokens_nano_bits,
                    bucket.last_refill_nanos,
                    bucket.transition_sequence,
                )
            })
            .unwrap_or_else(|| panic!("resumed token bucket state"));
        assert_eq!(resumed_token_state, token_state);
    }
}
