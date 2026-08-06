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
                                )?
                            } else {
                                NetworkFrameApplication::default()
                            };
                            output
                                .fault_continuation
                                .cursor_mut()
                                .complete(stage.target.clone(), phase)
                                .map_err(|error| SchedulerError::BoundaryViolation {
                                    message: format!(
                                        "network fault continuation cursor failed: {error}"
                                    ),
                                })?;
                            next_wakeup_nanos =
                                earliest_wakeup(next_wakeup_nanos, application.next_wakeup_nanos);
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
                                output
                                    .fault_continuation
                                    .cursor_mut()
                                    .defer_until(not_before_nanos, opportunity.id());
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
) -> Result<NetworkFrameApplication, SchedulerError> {
    let mut deferred_until = None;
    let mut queue_policy = None;
    let mut service_curves = Vec::new();
    let mut mtu_policy: Option<(&ResolvedBindingAction, &NetworkEffectSpecification)> = None;
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
        apply_network_mtu(payload, effects, action, specification)?
    } else {
        None
    };
    if let Some(expanded_payloads) = expanded_payloads {
        return Ok(NetworkFrameApplication {
            expanded_payloads,
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
            crucible::model::NetworkQueueOverflow::TypedError,
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
        next_wakeup_nanos: earliest_wakeup(
            defer_until,
            earliest_wakeup(
                state
                    .boundary
                    .next_wakeup_nanos(opportunity.coordinate().virtual_nanos),
                backpressure_wakeup,
            ),
        ),
        expanded_payloads: Vec::new(),
    })
}

#[derive(Clone, Debug, Default)]
struct NetworkFrameApplication {
    defer_until: Option<u64>,
    next_wakeup_nanos: Option<u64>,
    expanded_payloads: Vec<Vec<u8>>,
}

fn apply_network_mtu(
    payload: &[u8],
    effects: &mut crucible::ResolvedNetworkFrameEffects,
    action: &ResolvedBindingAction,
    specification: &NetworkEffectSpecification,
) -> Result<Option<Vec<Vec<u8>>>, SchedulerError> {
    let NetworkEffectSpecification::Mtu {
        mtu_bytes,
        oversize,
        fragmentation_protocol,
        ..
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
            Err(network_effect_application_error(
                action,
                "typed MTU response requires the generated-response scheduler phase",
            ))
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
                return Err(network_effect_application_error(
                    action,
                    "queue admission returned its configured typed overflow error",
                ));
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

fn network_service_finish(
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
            let declaration = topology.network_policy_artifact(intervals).ok_or_else(|| {
                network_effect_application_error(action, "contact plan disappeared")
            })?;
            let crucible::model::NetworkPolicyArtifactKind::ContactPlan { intervals } =
                &declaration.artifact
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
            let interval = intervals.iter().find(|interval| {
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
            let capacity = topology
                .network_policy_artifact(&interval.capacity_profile)
                .ok_or_else(|| {
                    network_effect_application_error(action, "contact capacity disappeared")
                })?;
            let crucible::model::NetworkPolicyArtifactKind::ServiceCurve { segments } =
                &capacity.artifact
            else {
                return Err(network_effect_application_error(
                    action,
                    "contact capacity changed type after admission",
                ));
            };
            let bits = u64::try_from(payload.len())
                .ok()
                .and_then(|bytes| bytes.checked_mul(8))
                .ok_or_else(|| {
                    network_effect_application_error(action, "contact frame size overflowed")
                })?;
            let finish = network_service_finish(
                now,
                bits,
                None,
                &[NetworkServiceCurveState {
                    activation_nanos: interval.start_nanos,
                    segments: segments.as_slice().to_vec(),
                }],
                action,
            )?;
            let traffic_end = interval
                .end_nanos
                .checked_sub(interval.teardown_nanos)
                .ok_or_else(|| {
                    network_effect_application_error(action, "contact teardown underflowed")
                })?;
            if finish > traffic_end {
                effects.mark_drop();
                return Ok(());
            }
            effects
                .add_delay(finish.checked_sub(now).ok_or_else(|| {
                    network_effect_application_error(action, "contact service regressed")
                })?)
                .map_err(map_effect_error)?;
            effects.mark_serialization_accounted();
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
            let lost = probability_fires(
                profile.loss,
                network_effect_draw(scenario_seed, opportunity, action, "rf-loss", 0),
            );
            let detected_error = probability_fires(
                profile.corruption,
                network_effect_draw(scenario_seed, opportunity, action, "rf-error", 0),
            );
            if lost || detected_error {
                effects
                    .add_delay(profile.retry_delay_nanos)
                    .map_err(map_effect_error)?;
                effects.mark_drop();
            }
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
        | NetworkEffectSpecification::SharedMedium { .. }
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

fn mapped_network_integers(action: &ResolvedBindingAction) -> Result<Vec<i64>, SchedulerError> {
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

fn lookup_network_integer_table(
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
                length_bytes: 1,
                payload_digest: ContentHash::from_bytes(&sequence.to_be_bytes()),
            },
        )
        .unwrap_or_else(|error| panic!("test opportunity should be valid: {error}"))
    }

    fn action_with_network_effect(
        specification: NetworkEffectSpecification,
    ) -> ResolvedBindingAction {
        let mut action = action();
        action.kind = BindingActionKind::Apply;
        action.phase = FaultPhase::Resolve;
        action.effect = Arc::new(
            EffectRequest::new(
                EFFECT_SEMANTIC_VERSION,
                EffectLifetime::Opportunity,
                EffectSpecification::Network(specification),
            )
            .unwrap_or_else(|error| panic!("test network effect: {error}")),
        );
        action
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
            .apply_frame(&reset.target, 49, &mut during_reset)
            .unwrap_or_else(|error| panic!("apply reset outage: {error}"));
        assert!(during_reset.is_dropped());
        let mut recovered = crucible::ResolvedNetworkFrameEffects::default();
        state
            .boundary
            .apply_frame(&reset.target, 50, &mut recovered)
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
}
