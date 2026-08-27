//! Ordered per-frame execution for signal-driven network effects.
//!
//! The route executor evaluates every declared target and phase, owns resumable
//! queue continuations, and composes exact per-frame outcomes before the
//! fault-free link delivery model receives a frame.

use super::*;

mod custody_and_payload;
mod frame_policy;

pub(super) use custody_and_payload::*;
pub(super) use frame_policy::*;

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
        let shared_cursor = Arc::clone(&self.cursor);
        let mut cursor = shared_cursor
            .lock()
            .map_err(|_| SchedulerError::BoundaryViolation {
                message: String::from("production fault evaluation cursor lock is poisoned"),
            })?;
        let cursor_before = *cursor;
        let shared_runtime = Arc::clone(&self.runtime);
        let mut runtime = shared_runtime
            .lock()
            .map_err(|_| SchedulerError::BoundaryViolation {
                message: String::from("production fault runtime lock is poisoned"),
            })?;
        let mut staged_scheduler = loop_impl.clone();
        let mut staged_pending = pending_outputs.clone();
        let source_outputs = outputs.clone();
        let mut routed = Vec::new();
        let mut observation_batches = Vec::new();
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
                        && let Some(path) = stages.iter().find_map(|stage| match &stage.target {
                            crucible::model::ResolvedFaultTarget::NetworkPath {
                                path_version,
                                ..
                            } => Some(path_version.clone()),
                            _ => None,
                        })
                    {
                        output.fault_continuation.cursor_mut().lock_route_path(path);
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
                            let sequence = cursor.next_sequence(frontier.ticks)?;
                            let host_before = runtime.host_state().clone();
                            let evaluation = runtime
                                .evaluate_opportunity(
                                    &opportunity,
                                    sequence.same_coordinate,
                                    _backend,
                                )
                                .map_err(|error| SchedulerError::BoundaryViolation {
                                    message: format!(
                                        "signal network opportunity failed closed: {error}"
                                    ),
                                })?;
                            super::super::fault_implementation::require_network_actions_implemented(
                                evaluation.actions.iter(),
                            )
                            .map_err(|error| SchedulerError::BoundaryViolation {
                                message: format!(
                                    "network frame action is absent from the production implementation registry: {error}"
                                ),
                            })?;
                            runtime_committed = true;
                            next_wakeup_nanos =
                                earliest_wakeup(next_wakeup_nanos, evaluation.next_wakeup_nanos);
                            let impulses = runtime.drain_host_impulses();
                            let (transition_observations, records) = self
                                .stage_availability_transition_drops(
                                    opportunity.coordinate(),
                                    &evaluation.actions,
                                    &host_before,
                                    &mut staged_scheduler,
                                    &mut staged_pending,
                                    Some(&mut routed),
                                )?;
                            let mut evaluation_observations = evaluation.observations;
                            evaluation_observations.extend(transition_observations);
                            observation_batches.push((sequence.journal, evaluation_observations));
                            transition_records.extend(records);
                            let mut frame_actions = Vec::new();
                            staged_effect_state.boundary.apply_frame(
                                opportunity.target(),
                                output.fault_continuation.cursor().route_path_version(),
                                &self.topology,
                                frontier.ticks,
                                &mut resolved_effects,
                            )?;
                            for action in runtime.host_state().matching(opportunity.target(), phase)
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
                            super::super::fault_implementation::require_network_actions_implemented(
                                frame_actions.iter(),
                            )
                            .map_err(|error| SchedulerError::BoundaryViolation {
                                message: format!(
                                    "active network frame action is absent from the production implementation registry: {error}"
                                ),
                            })?;
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
                                apply_network_frame_actions_with_limits(
                                    &mut output.payload,
                                    &mut resolved_effects,
                                    &frame_actions,
                                    &opportunity,
                                    runtime.scenario_seed().ok_or_else(|| {
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
                                    self.resource_limits,
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
                                    self.resource_limits,
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
                                    stage_pending_network_output(
                                        &mut staged_pending,
                                        rerouted,
                                        self.resource_limits,
                                    )?;
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
                                            self.resource_limits,
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
                                stage_pending_network_output(
                                    &mut staged_pending,
                                    output,
                                    self.resource_limits,
                                )?;
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
            staged_scheduler
                .record_pending_signal_fault_search_frontiers(runtime.drain_search_choices())?;
            let mut journal =
                self.observations
                    .lock()
                    .map_err(|_| SchedulerError::BoundaryViolation {
                        message: String::from(
                            "production fault observation journal lock is poisoned",
                        ),
                    })?;
            journal
                .append_observation_batches(observation_batches)
                .map_err(|error| SchedulerError::BoundaryViolation {
                    message: error.to_string(),
                })?;
            let observations = journal.drain_ready(
                staged_scheduler
                    .condition_event_log_prefix()
                    .point()
                    .at()
                    .ticks,
            );
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
                    runtime.poison();
                } else {
                    *cursor = cursor_before;
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

fn network_contact_entry_count(state: &NetworkEffectRuntimeState) -> Option<usize> {
    state
        .contact_services
        .len()
        .checked_add(network_contact_reservation_count(state)?)
}

fn admit_network_contact_service_keys(
    state: &NetworkEffectRuntimeState,
    keys: &BTreeSet<NetworkContactServiceKey>,
    additional_reservations: usize,
    resource_limits: FaultResourceLimits,
) -> Result<(), SchedulerError> {
    let additional = keys
        .iter()
        .filter(|key| !state.contact_services.contains_key(*key))
        .count();
    let current = network_contact_entry_count(state).ok_or_else(|| {
        map_network_resource_limit(
            FaultResourceLimitError::Representation {
                field: "network_contact_entries",
                value: u64::MAX,
            },
            resource_limits,
        )
    })?;
    let requested = additional
        .checked_add(additional_reservations)
        .ok_or_else(|| {
            map_network_resource_limit(
                FaultResourceLimitError::Representation {
                    field: "network_contact_entries",
                    value: u64::MAX,
                },
                resource_limits,
            )
        })?;
    reserve_network_resource(
        "network_contact_entries",
        current,
        requested,
        resource_limits,
    )
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

// crucible-lint: allow rust-allow -- frame mutation joins independently authenticated opportunity, topology, state, and output owners.
#[allow(
    clippy::too_many_arguments,
    reason = "frame mutation joins the independently authenticated opportunity, topology, state, and output owners"
)]
fn apply_network_frame_actions_with_limits(
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
    resource_limits: FaultResourceLimits,
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
                let release = apply_network_shared_medium_with_limits(
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
                    resource_limits,
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
                let application = apply_network_custody_queue_with_limits(
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
                    resource_limits,
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
            NetworkEffectSpecification::Availability { .. }
            | NetworkEffectSpecification::Flap { .. }
            | NetworkEffectSpecification::NegotiatedMode { .. }
            | NetworkEffectSpecification::ProfileDelta { .. }
            | NetworkEffectSpecification::PropagationDelay { .. }
            | NetworkEffectSpecification::AccessDelay { .. }
            | NetworkEffectSpecification::Jitter { .. }
            | NetworkEffectSpecification::FrameLoss { .. }
            | NetworkEffectSpecification::Duplicate { .. }
            | NetworkEffectSpecification::Reorder { .. }
            | NetworkEffectSpecification::PayloadTransform { .. }
            | NetworkEffectSpecification::DetectedFrameError { .. }
            | NetworkEffectSpecification::RecipientSubset { .. }
            | NetworkEffectSpecification::ForwarderLifecycle { .. }
            | NetworkEffectSpecification::RouteTransition { .. }
            | NetworkEffectSpecification::ControlPlaneService { .. }
            | NetworkEffectSpecification::Association { .. }
            | NetworkEffectSpecification::ControlResultTransform { .. }
            | NetworkEffectSpecification::Contact { .. }
            | NetworkEffectSpecification::RfChannel { .. } => {
                apply_network_frame_action_with_limits(
                    payload,
                    effects,
                    action,
                    opportunity,
                    scenario_seed,
                    topology,
                    state,
                    resource_limits,
                )?
            }
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
            resource_limits,
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
            resource_limits.network_queue_bytes,
            resource_limits.network_queue_frames,
            crucible::model::NetworkQueueDiscipline::Fifo,
            None,
            crucible::model::NetworkQueueOverflow::TailDrop,
            None,
            &mut typed_response,
            effects.serialization_rate_cap_bps().or(base_rate_bps),
            &service_curves,
            deferred_until,
            resource_limits,
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

#[cfg(test)]
// crucible-lint: allow rust-allow -- the compatibility wrapper mirrors the complete production frame-action boundary.
#[allow(clippy::too_many_arguments)]
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
    apply_network_frame_actions_with_limits(
        payload,
        effects,
        actions,
        opportunity,
        scenario_seed,
        topology,
        state,
        pending_outputs,
        base_rate_bps,
        repeated_phase_effect,
        FaultResourceLimits::default(),
    )
}

#[cfg(test)]
#[path = "route_tests.rs"]
mod tests;
