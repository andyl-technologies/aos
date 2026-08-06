//! Production ownership of signal-driven network interception.
//!
//! The interceptor lives inside the backend quantum loop so committed QEMU
//! frames cannot bypass the exact pre-routing fault boundary. The executable
//! network adapter is layered onto this owner; the runtime itself is never
//! shared through a test-only or process-global side channel.

use super::*;
use crucible::model::{
    BindingActionKind, ContentHash, EffectSpecification, FAULT_RUNTIME_STATE_VERSION,
    FaultObjectId, FaultObservation, FaultObservationKind, FaultOpportunity, FaultPhase,
    NetworkAvailabilityState, NetworkEffectSpecification, NetworkInFlightPolicy,
    OpportunityPayload, ResolvedBindingAction,
};
use crucible::{BackendNetworkOutputInterceptor, SchedulerEventLogAppend};

#[derive(Clone, Debug)]
struct NetworkAvailabilityTransitionRecord {
    action: ContentHash,
    binding: FaultObjectId,
    target: crucible::model::ResolvedFaultTarget,
    phase: FaultPhase,
    transition_sequence: u64,
    old_state: NetworkAvailabilityState,
    state: NetworkAvailabilityState,
    queued_policy: NetworkInFlightPolicy,
    in_flight_policy: NetworkInFlightPolicy,
    source: crucible::NodeId,
    destination: crucible::NodeId,
    in_flight: crucible::NetworkInFlightDropEvidence,
    queued: Vec<crucible::BackendNetworkOutput>,
    evidence: ContentHash,
}

/// Owns the production signal continuation at the pre-routing network seam.
pub(super) struct ProductionFaultNetworkInterceptor {
    runtime: ProductionFaultRuntime,
    topology: crucible::model::WorldFaultTopology,
    links: Vec<crucible::LinkDef>,
    coordinate: Option<u64>,
    coordinate_sequence: u64,
    transition_ledger: Vec<NetworkAvailabilityTransitionRecord>,
}

impl ProductionFaultNetworkInterceptor {
    /// Creates an interceptor around the admitted production continuation.
    #[must_use]
    pub(super) const fn new(
        runtime: ProductionFaultRuntime,
        topology: crucible::model::WorldFaultTopology,
        links: Vec<crucible::LinkDef>,
    ) -> Self {
        Self {
            runtime,
            topology,
            links,
            coordinate: None,
            coordinate_sequence: 0,
            transition_ledger: Vec::new(),
        }
    }

    /// Captures the fault runtime together with all network adapter state.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] if the scheduler/pending state cannot be
    /// encoded or a live QEMU node cannot supply checkpoint evidence.
    pub(super) fn checkpoint(
        &self,
        scheduler: &SingleScheduler,
        pending_outputs: &[crucible::BackendNetworkOutput],
        backend: &mut ProductionNodeSet,
    ) -> Result<ProductionFaultRuntimeCheckpoint, SchedulerError> {
        let network_state = self.network_state_digest(scheduler, pending_outputs)?;
        self.runtime
            .checkpoint_with_network_state(backend, network_state)
            .map_err(|error| SchedulerError::BoundaryViolation {
                message: format!("capture production fault continuation: {error}"),
            })
    }

    fn network_state_digest(
        &self,
        scheduler: &SingleScheduler,
        pending_outputs: &[crucible::BackendNetworkOutput],
    ) -> Result<ContentHash, SchedulerError> {
        let mut material = Vec::new();
        material.extend_from_slice(&scheduler.network_continuation_digest()?.bytes);
        material.extend_from_slice(&self.coordinate.unwrap_or(u64::MAX).to_be_bytes());
        material.extend_from_slice(&self.coordinate_sequence.to_be_bytes());
        let pending_count = u64::try_from(pending_outputs.len()).map_err(|_error| {
            SchedulerError::BoundaryViolation {
                message: String::from("pending network output count exceeds the checkpoint width"),
            }
        })?;
        material.extend_from_slice(&pending_count.to_be_bytes());
        for output in pending_outputs {
            append_backend_output_evidence(&mut material, output)?;
        }
        let transition_count = u64::try_from(self.transition_ledger.len()).map_err(|_error| {
            SchedulerError::BoundaryViolation {
                message: String::from("network transition count exceeds the checkpoint width"),
            }
        })?;
        material.extend_from_slice(&transition_count.to_be_bytes());
        for transition in &self.transition_ledger {
            material.extend_from_slice(&transition.action.bytes);
            append_evidence_bytes(&mut material, transition.binding.as_str().as_bytes())?;
            append_evidence_bytes(&mut material, transition.target.kind().as_str().as_bytes())?;
            append_evidence_bytes(&mut material, transition.phase.as_str().as_bytes())?;
            material.extend_from_slice(&transition.transition_sequence.to_be_bytes());
            material.push(availability_state_tag(transition.old_state));
            material.push(availability_state_tag(transition.state));
            material.push(in_flight_policy_tag(transition.queued_policy));
            material.push(in_flight_policy_tag(transition.in_flight_policy));
            append_evidence_bytes(&mut material, transition.source.name.as_bytes())?;
            append_evidence_bytes(&mut material, transition.destination.name.as_bytes())?;
            material.extend_from_slice(&transition.in_flight.evidence.bytes);
            for output in &transition.queued {
                append_backend_output_evidence(&mut material, output)?;
            }
            material.extend_from_slice(&transition.evidence.bytes);
        }
        Ok(ContentHash::from_bytes(&material))
    }

    /// Evaluates one ordered scheduler boundary through the owned continuation.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when the per-coordinate sequence overflows or
    /// the production runtime rejects evaluation.
    pub(super) fn evaluate_boundary(
        &mut self,
        coordinate: FaultCoordinate,
        scheduler: &mut SingleScheduler,
        backend: &mut ProductionNodeSet,
        pending_outputs: &mut Vec<crucible::BackendNetworkOutput>,
    ) -> Result<SchedulerEventLogAppend, SchedulerError> {
        let sequence = self.next_sequence(coordinate.virtual_nanos)?;
        let mut staged_scheduler = scheduler.clone();
        let mut staged_pending = pending_outputs.clone();
        let host_before = self.runtime.host_state().clone();
        let mut evaluation = self
            .runtime
            .evaluate_boundary(coordinate, sequence, backend)
            .map_err(|error| SchedulerError::BoundaryViolation {
                message: format!("signal fault boundary failed closed: {error}"),
            })?;
        let staged = (|| {
            let impulses = self.runtime.drain_host_impulses();
            if !impulses.is_empty() {
                return Err(SchedulerError::BoundaryViolation {
                    message: String::from(
                        "network availability produced an invalid boundary impulse action",
                    ),
                });
            }
            let (observations, records) = self.stage_availability_transition_drops(
                coordinate,
                &evaluation.actions,
                &host_before,
                &mut staged_scheduler,
                &mut staged_pending,
                None,
            )?;
            evaluation.observations.extend(observations);
            staged_scheduler.set_signal_fault_wakeup(evaluation.next_wakeup_nanos)?;
            let append = staged_scheduler.append_fault_observations(evaluation.observations)?;
            Ok((append, records))
        })();
        let (append, records) = match staged {
            Ok(staged) => staged,
            Err(error) => {
                self.runtime.poison();
                return Err(error);
            }
        };
        *scheduler = staged_scheduler;
        *pending_outputs = staged_pending;
        self.transition_ledger.extend(records);
        Ok(append)
    }

    fn stage_availability_transition_drops(
        &self,
        coordinate: FaultCoordinate,
        actions: &[ResolvedBindingAction],
        host_before: &crucible::model::HostFaultActionState,
        scheduler: &mut SingleScheduler,
        queued_outputs: &mut Vec<crucible::BackendNetworkOutput>,
        ready_outputs: Option<&mut Vec<crucible::BackendNetworkOutput>>,
    ) -> Result<
        (
            Vec<FaultObservation>,
            Vec<NetworkAvailabilityTransitionRecord>,
        ),
        SchedulerError,
    > {
        let transitions = actions
            .iter()
            .filter(|action| action.kind == BindingActionKind::UpsertPersistent)
            .filter_map(|action| {
                let EffectSpecification::Network(NetworkEffectSpecification::Availability {
                    state,
                    ..
                }) = action.effect.specification()
                else {
                    return None;
                };
                (*state != NetworkAvailabilityState::Up).then_some(action)
            })
            .collect::<Vec<_>>();
        if transitions.is_empty() {
            return Ok((Vec::new(), Vec::new()));
        }

        let mut blockers =
            BTreeMap::<(crucible::NodeId, crucible::NodeId), Vec<&ResolvedBindingAction>>::new();
        for link in &self.links {
            let (endpoint_a, endpoint_b) = link.endpoints();
            for (source, destination) in [(endpoint_a, endpoint_b), (endpoint_b, endpoint_a)] {
                let stages = self
                    .topology
                    .network_route_fault_targets(
                        &source.name,
                        &destination.name,
                        coordinate.virtual_nanos,
                    )
                    .map_err(|error| SchedulerError::BoundaryViolation {
                        message: format!(
                            "cannot resolve availability transition route `{}` to `{}`: {error}",
                            source.name, destination.name
                        ),
                    })?;
                let matching = transitions
                    .iter()
                    .copied()
                    .filter(|action| transition_blocks_route(action, &stages))
                    .collect::<Vec<_>>();
                if !matching.is_empty() {
                    blockers.insert((source.clone(), destination.clone()), matching);
                }
            }
        }

        let mut queued_by_route = BTreeMap::<
            (crucible::NodeId, crucible::NodeId),
            Vec<crucible::BackendNetworkOutput>,
        >::new();
        partition_transition_queued_outputs(
            scheduler,
            &blockers,
            queued_outputs,
            &mut queued_by_route,
        )?;
        if let Some(ready_outputs) = ready_outputs {
            partition_transition_queued_outputs(
                scheduler,
                &blockers,
                ready_outputs,
                &mut queued_by_route,
            )?;
        }

        let mut observations = Vec::new();
        let mut records = Vec::new();
        for ((source, destination), route_blockers) in blockers {
            let destructive_in_flight = route_blockers.iter().any(|action| {
                let EffectSpecification::Network(NetworkEffectSpecification::Availability {
                    in_flight_policy,
                    ..
                }) = action.effect.specification()
                else {
                    return false;
                };
                *in_flight_policy != NetworkInFlightPolicy::Preserve
            });
            let in_flight = if destructive_in_flight {
                scheduler.drop_network_inflight_for_route(&source, &destination)?
            } else {
                let mut preview = scheduler.clone();
                preview.drop_network_inflight_for_route(&source, &destination)?
            };
            let queued = queued_by_route
                .remove(&(source.clone(), destination.clone()))
                .unwrap_or_default();
            if in_flight.frame_count == 0 && queued.is_empty() {
                continue;
            }
            for action in route_blockers {
                let EffectSpecification::Network(NetworkEffectSpecification::Availability {
                    state,
                    queued_policy,
                    in_flight_policy,
                }) = action.effect.specification()
                else {
                    continue;
                };
                let old_state = host_before
                    .matching(&action.target, action.phase)
                    .find(|prior| prior.binding == action.binding)
                    .and_then(|prior| {
                        let EffectSpecification::Network(
                            NetworkEffectSpecification::Availability { state, .. },
                        ) = prior.effect.specification()
                        else {
                            return None;
                        };
                        Some(*state)
                    })
                    .unwrap_or(NetworkAvailabilityState::Up);
                let evidence = availability_transition_evidence(
                    action,
                    old_state,
                    *state,
                    *queued_policy,
                    *in_flight_policy,
                    &source,
                    &destination,
                    &in_flight,
                    &queued,
                )?;
                observations.push(FaultObservation {
                    semantic_version: FAULT_RUNTIME_STATE_VERSION,
                    kind: FaultObservationKind::NetworkProfile,
                    coordinate,
                    binding: Some(action.binding.clone()),
                    target: Some(action.target.clone()),
                    opportunity: action.opportunity,
                    evidence,
                });
                if *queued_policy == NetworkInFlightPolicy::TypedError
                    || *in_flight_policy == NetworkInFlightPolicy::TypedError
                {
                    observations.push(FaultObservation {
                        semantic_version: FAULT_RUNTIME_STATE_VERSION,
                        kind: FaultObservationKind::EffectRejected,
                        coordinate,
                        binding: Some(action.binding.clone()),
                        target: Some(action.target.clone()),
                        opportunity: action.opportunity,
                        evidence,
                    });
                }
                records.push(NetworkAvailabilityTransitionRecord {
                    action: action.id(),
                    binding: action.binding.clone(),
                    target: action.target.clone(),
                    phase: action.phase,
                    transition_sequence: action.transition_sequence,
                    old_state,
                    state: *state,
                    queued_policy: *queued_policy,
                    in_flight_policy: *in_flight_policy,
                    source: source.clone(),
                    destination: destination.clone(),
                    in_flight: in_flight.clone(),
                    queued: queued.clone(),
                    evidence,
                });
            }
        }
        Ok((observations, records))
    }

    fn next_sequence(&mut self, coordinate: u64) -> Result<u64, SchedulerError> {
        if self.coordinate == Some(coordinate) {
            self.coordinate_sequence =
                self.coordinate_sequence.checked_add(1).ok_or_else(|| {
                    SchedulerError::BoundaryViolation {
                        message: String::from(
                            "signal fault same-coordinate sequence space is exhausted",
                        ),
                    }
                })?;
        } else {
            self.coordinate = Some(coordinate);
            self.coordinate_sequence = 0;
        }
        Ok(self.coordinate_sequence)
    }
}

fn transition_blocks_route(
    action: &ResolvedBindingAction,
    stages: &[crucible::model::WorldNetworkRouteFaultTarget],
) -> bool {
    let EffectSpecification::Network(NetworkEffectSpecification::Availability { state, .. }) =
        action.effect.specification()
    else {
        return false;
    };
    stages.iter().any(|stage| {
        stage.target == action.target
            && stage.phases().contains(&action.phase)
            && !availability_allows(*state, stage.direction)
    })
}

fn partition_transition_queued_outputs(
    scheduler: &SingleScheduler,
    blockers: &BTreeMap<(crucible::NodeId, crucible::NodeId), Vec<&ResolvedBindingAction>>,
    outputs: &mut Vec<crucible::BackendNetworkOutput>,
    dropped: &mut BTreeMap<
        (crucible::NodeId, crucible::NodeId),
        Vec<crucible::BackendNetworkOutput>,
    >,
) -> Result<(), SchedulerError> {
    let mut retained = Vec::new();
    for output in std::mem::take(outputs) {
        for route in scheduler.resolve_backend_network_routes(&output)? {
            let key = (output.source.clone(), route.destination.clone());
            let mut routed = output.clone();
            routed.destination = route.destination.clone();
            routed.route = Some(route);
            let Some(route_blockers) = blockers.get(&key) else {
                retained.push(routed);
                continue;
            };
            let mut destructive = false;
            for action in route_blockers {
                let EffectSpecification::Network(NetworkEffectSpecification::Availability {
                    queued_policy,
                    ..
                }) = action.effect.specification()
                else {
                    continue;
                };
                if *queued_policy == NetworkInFlightPolicy::Preserve {
                    routed
                        .fault_continuation
                        .preserve_availability(action.binding.clone(), action.phase);
                } else {
                    destructive = true;
                }
            }
            dropped.entry(key).or_default().push(routed.clone());
            if !destructive {
                retained.push(routed);
            }
        }
    }
    *outputs = retained;
    Ok(())
}

fn availability_transition_evidence(
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

fn append_backend_output_evidence(
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
        append_evidence_bytes(material, preserved.phase.as_str().as_bytes())?;
    }
    append_evidence_bytes(material, &output.payload)
}

fn append_evidence_bytes(output: &mut Vec<u8>, value: &[u8]) -> Result<(), SchedulerError> {
    let length =
        u64::try_from(value.len()).map_err(|_error| SchedulerError::BoundaryViolation {
            message: String::from("network transition evidence value exceeds the canonical width"),
        })?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

const fn availability_state_tag(state: NetworkAvailabilityState) -> u8 {
    match state {
        NetworkAvailabilityState::Up => 1,
        NetworkAvailabilityState::Down => 2,
        NetworkAvailabilityState::ReceiveOnly => 3,
        NetworkAvailabilityState::TransmitOnly => 4,
    }
}

const fn in_flight_policy_tag(policy: NetworkInFlightPolicy) -> u8 {
    match policy {
        NetworkInFlightPolicy::Preserve => 1,
        NetworkInFlightPolicy::Reevaluate => 2,
        NetworkInFlightPolicy::Drop => 3,
        NetworkInFlightPolicy::TypedError => 4,
    }
}

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
        let mut staged_scheduler = loop_impl.clone();
        let mut staged_pending = pending_outputs.clone();
        let source_outputs = outputs.clone();
        let mut routed = Vec::new();
        let mut observations = Vec::new();
        let mut transition_records = Vec::new();
        let mut next_wakeup_nanos = None;
        let mut runtime_committed = false;
        let staged = (|| {
            for output in source_outputs {
                for route in staged_scheduler.resolve_backend_network_routes(&output)? {
                    let stages = self
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
                    let mut output = output.clone();
                    output.route = Some(route);
                    let producer = FaultObjectId::parse(&output.source.name).map_err(|error| {
                    SchedulerError::BoundaryViolation {
                        message: format!(
                            "network frame producer `{}` is not a canonical fault object: {error}",
                            output.source.name
                        ),
                    }
                })?;
                    let length_bytes = u64::try_from(output.payload.len()).map_err(|_error| {
                        SchedulerError::BoundaryViolation {
                            message: String::from(
                                "network frame length exceeds the fault ABI width",
                            ),
                        }
                    })?;
                    let payload = OpportunityPayload::NetworkFrame {
                        producer,
                        producer_sequence: output.sequence,
                        length_bytes,
                        payload_digest: ContentHash::from_bytes(&output.payload),
                    };
                    let mut admitted = true;
                    for stage in &stages {
                        for phase in [FaultPhase::Admit, FaultPhase::Resolve] {
                            if !stage.phases().contains(&phase) {
                                continue;
                            }
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
                            if !impulses.is_empty() {
                                return Err(SchedulerError::BoundaryViolation {
                                    message: String::from(
                                        "network availability produced an invalid impulse action",
                                    ),
                                });
                            }
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
                            for action in self
                                .runtime
                                .host_state()
                                .matching(opportunity.target(), phase)
                            {
                                if output
                                    .fault_continuation
                                    .preserves_availability(&action.binding, phase)
                                {
                                    continue;
                                }
                                let EffectSpecification::Network(
                                    NetworkEffectSpecification::Availability { state, .. },
                                ) = action.effect.specification()
                                else {
                                    return Err(SchedulerError::BoundaryViolation {
                                        message: format!(
                                            "production network admission encountered unadvertised effect `{}`",
                                            action.effect.kind().as_str()
                                        ),
                                    });
                                };
                                admitted &= availability_allows(*state, stage.direction);
                            }
                        }
                    }
                    if admitted {
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
                }
                return Err(error);
            }
        };
        *loop_impl = staged_scheduler;
        *pending_outputs = staged_pending;
        *outputs = routed;
        self.transition_ledger.extend(transition_records);
        Ok(appends)
    }
}

fn earliest_wakeup(current: Option<u64>, candidate: Option<u64>) -> Option<u64> {
    match (current, candidate) {
        (Some(current), Some(candidate)) => Some(current.min(candidate)),
        (Some(current), None) => Some(current),
        (None, candidate) => candidate,
    }
}

fn availability_allows(
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crucible::model::{
        BindingMapping, BindingObservabilityPolicy, BindingSampling, BindingSearchPolicy,
        EFFECT_SEMANTIC_VERSION, EffectLifetime, EffectRequest, EvaluatedSignal, FaultBinding,
        FaultDirection, InverseCdfTable, NetworkInFlightPolicy, ResolvedFaultTarget,
        ResolvedTargetSet, SampleObservation, SignalChoiceContext, SignalCoordinate, SignalDomain,
        SignalEvaluationError, SignalId, SignalNode, SignalNodeKind, SignalResourceLimits,
        SignalShape, SignalSourceSpecification, SignalUnit, SignalValue, SignalValueType,
        TargetSelector, WorldNetworkInterface, WorldNetworkSegment, WorldNetworkSegmentKind,
        WorldNetworkTechnology,
    };
    use crucible::{
        BackendNetworkOutput, Icount, LinkDef, MemoryDagStore, QuantumLoop, ReadyPoint,
        SchedulerLivenessScenario, Shift, SimInstant, VmArchitecture, WhiteBoxPolicy,
        WorldIoLayoutPolicy, WorldNode, deterministic_node_mac,
    };

    struct NoArtifacts;

    impl crucible::model::SignalArtifactProvider for NoArtifacts {
        fn inverse_cdf_table(
            &self,
            content: &ContentHash,
        ) -> Result<InverseCdfTable, SignalEvaluationError> {
            Err(SignalEvaluationError::ArtifactContentMismatch(*content))
        }

        fn evaluate_artifact_source(
            &self,
            node: &SignalNode,
            _source: &SignalSourceSpecification,
            _coordinate: &SignalCoordinate,
            _same_coordinate_sequence: u64,
            _choice: &SignalChoiceContext,
            _inputs: &[EvaluatedSignal],
        ) -> Result<EvaluatedSignal, SignalEvaluationError> {
            Err(SignalEvaluationError::ArtifactSourceRequired(
                node.id.clone(),
            ))
        }
    }

    fn object_id(value: &str) -> FaultObjectId {
        FaultObjectId::parse(value)
            .unwrap_or_else(|error| panic!("test object ID should be valid: {error}"))
    }

    fn signal_id(value: &str) -> SignalId {
        SignalId::parse(value)
            .unwrap_or_else(|error| panic!("test signal ID should be valid: {error}"))
    }

    fn node(name: &str) -> WorldNode {
        WorldNode {
            id: crucible::NodeId {
                name: name.to_owned(),
            },
            arch: VmArchitecture::X86_64,
            memory_mib: 128,
            cmdline: String::new(),
            ready_point: ReadyPoint::FixedIcount {
                icount: Icount { retired: 0 },
            },
            white_box: WhiteBoxPolicy::Disabled,
            smp_vcpus: 1,
            icount_shift: 0,
            kernel: None,
            root_image: None,
            initrd: None,
        }
    }

    fn availability_world() -> (crucible::World, FaultObjectId) {
        let link = LinkDef::new(
            crucible::NodeId {
                name: String::from("left"),
            },
            crucible::NodeId {
                name: String::from("right"),
            },
        )
        .unwrap_or_else(|error| panic!("test link should be valid: {error}"));
        let segment = link
            .fault_segment_id()
            .unwrap_or_else(|error| panic!("test segment ID should be valid: {error}"));
        let segment_signal = SignalId::parse(segment.as_str())
            .unwrap_or_else(|error| panic!("test segment signal ID should be valid: {error}"));
        let topology = crucible::model::WorldFaultTopology {
            network_interfaces: vec![
                WorldNetworkInterface {
                    id: signal_id("left-interface"),
                    endpoint: signal_id("left"),
                    technology: WorldNetworkTechnology::Ethernet,
                    addresses: Vec::new(),
                    fault_domains: Vec::new(),
                },
                WorldNetworkInterface {
                    id: signal_id("right-interface"),
                    endpoint: signal_id("right"),
                    technology: WorldNetworkTechnology::Ethernet,
                    addresses: Vec::new(),
                    fault_domains: Vec::new(),
                },
            ],
            network_segments: vec![WorldNetworkSegment {
                id: segment_signal,
                kind: WorldNetworkSegmentKind::Ethernet,
                interface_a: signal_id("left-interface"),
                interface_b: signal_id("right-interface"),
                minimum_latency_nanos: 1,
                medium: None,
                forwarders: Vec::new(),
                fault_domains: Vec::new(),
            }],
            ..crucible::model::WorldFaultTopology::default()
        };
        let world =
            crucible::World::from_nodes_and_links(vec![node("left"), node("right")], vec![link])
                .unwrap_or_else(|error| panic!("test World should be valid: {error}"))
                .with_fault_topology(topology)
                .unwrap_or_else(|error| panic!("test fault topology should be valid: {error}"));
        (world, segment)
    }

    fn down_plan(segment: FaultObjectId) -> crucible::model::FaultSignalPlan {
        down_plan_at(segment, FaultPhase::Admit)
    }

    fn down_plan_at(segment: FaultObjectId, phase: FaultPhase) -> crucible::model::FaultSignalPlan {
        down_plan_with_policies(
            segment,
            phase,
            NetworkInFlightPolicy::Drop,
            NetworkInFlightPolicy::Drop,
        )
    }

    fn down_plan_with_policies(
        segment: FaultObjectId,
        phase: FaultPhase,
        queued_policy: NetworkInFlightPolicy,
        in_flight_policy: NetworkInFlightPolicy,
    ) -> crucible::model::FaultSignalPlan {
        let output = signal_id("network-down");
        let program = crucible::model::SignalProgram::new(
            vec![SignalNode {
                id: output.clone(),
                domain: SignalDomain::VirtualTime,
                output: SignalShape::new(SignalValueType::Bool, SignalUnit::Dimensionless, 0)
                    .unwrap_or_else(|error| panic!("test shape should be valid: {error}")),
                inputs: Vec::new(),
                kind: SignalNodeKind::Constant {
                    value: SignalValue::Bool(true),
                },
            }],
            vec![output],
            SignalResourceLimits::default(),
        )
        .unwrap_or_else(|error| panic!("test program should be valid: {error}"));
        let targets = ResolvedTargetSet::new(
            vec![ResolvedFaultTarget::NetworkSegment {
                segment,
                direction: FaultDirection::AToB,
            }],
            false,
        )
        .unwrap_or_else(|error| panic!("test targets should be valid: {error}"));
        let effect = EffectRequest::new(
            EFFECT_SEMANTIC_VERSION,
            EffectLifetime::Persistent,
            EffectSpecification::Network(NetworkEffectSpecification::Availability {
                state: NetworkAvailabilityState::Down,
                queued_policy,
                in_flight_policy,
            }),
        )
        .unwrap_or_else(|error| panic!("test effect should be valid: {error}"));
        let binding = FaultBinding::new(
            object_id("network-down-binding"),
            program.exported_outputs().to_vec(),
            BindingSampling::AtBoundary,
            BindingMapping::ActiveWhenTrue { invert: false },
            TargetSelector::Exact(targets),
            [phase].into_iter().collect(),
            effect,
            None,
            BindingSearchPolicy::Fixed,
            BindingObservabilityPolicy {
                samples: SampleObservation::ChangesAndEffects,
                record_inactive_opportunities: false,
                retain_mapped_values: true,
            },
            &program,
        )
        .unwrap_or_else(|error| panic!("test binding should be valid: {error}"));
        crucible::model::FaultSignalPlan::new(vec![program], vec![binding])
            .unwrap_or_else(|error| panic!("test plan should be valid: {error}"))
    }

    #[test]
    fn directional_availability_has_a_closed_lattice() {
        for direction in [
            FaultDirection::AToB,
            FaultDirection::BToA,
            FaultDirection::Ingress,
            FaultDirection::Egress,
        ] {
            assert!(availability_allows(NetworkAvailabilityState::Up, direction));
            assert!(!availability_allows(
                NetworkAvailabilityState::Down,
                direction
            ));
        }
        assert!(availability_allows(
            NetworkAvailabilityState::ReceiveOnly,
            FaultDirection::Ingress
        ));
        assert!(!availability_allows(
            NetworkAvailabilityState::ReceiveOnly,
            FaultDirection::Egress
        ));
        assert!(availability_allows(
            NetworkAvailabilityState::TransmitOnly,
            FaultDirection::Egress
        ));
        assert!(!availability_allows(
            NetworkAvailabilityState::TransmitOnly,
            FaultDirection::Ingress
        ));
    }

    #[test]
    fn production_boundary_drops_a_preexisting_world_link_frame() {
        let (world, segment) = availability_world();
        let scenario = SchedulerLivenessScenario::from_runnable_world(
            "production-availability-drop",
            Shift::default(),
            16,
            SimInstant { nanos: 128 },
            0,
            &world,
        );
        let mut scheduler = SingleScheduler::from_world(
            scenario,
            &world,
            &MemoryDagStore::new(),
            WorldIoLayoutPolicy::default(),
        )
        .unwrap_or_else(|error| panic!("test scheduler should build: {error}"));
        let source = crucible::NodeId {
            name: String::from("left"),
        };
        let destination = crucible::NodeId {
            name: String::from("right"),
        };
        let mut payload = vec![0_u8; 14];
        payload[..6].copy_from_slice(&deterministic_node_mac(&destination));
        QuantumLoop::append_backend_network_outputs(
            &mut scheduler,
            vec![BackendNetworkOutput {
                source: source.clone(),
                destination: destination.clone(),
                emit_icount: Icount { retired: 0 },
                sequence: 1,
                payload,
                route: None,
                fault_continuation: Default::default(),
            }],
        )
        .unwrap_or_else(|error| panic!("test frame should route: {error}"));

        let nodes = ProductionNodeSet::new();
        let runtime = ProductionFaultRuntime::new(
            down_plan(segment),
            Some(Arc::new(NoArtifacts)),
            SignalBoundarySnapshot::default(),
            ContentHash::from_bytes(b"production-availability-drop"),
            &nodes,
        )
        .unwrap_or_else(|error| panic!("test fault runtime should build: {error}"));
        let mut interceptor = ProductionFaultNetworkInterceptor::new(
            runtime,
            world.fault_topology().clone(),
            world.links().to_vec(),
        );
        let mut nodes = nodes;
        let mut queued_forward_payload = vec![0_u8; 14];
        queued_forward_payload[..6].copy_from_slice(&deterministic_node_mac(&destination));
        let mut queued_reverse_payload = vec![0_u8; 14];
        queued_reverse_payload[..6].copy_from_slice(&deterministic_node_mac(&source));
        let mut pending_outputs = vec![
            BackendNetworkOutput {
                source: source.clone(),
                destination: destination.clone(),
                emit_icount: Icount { retired: 7 },
                sequence: 2,
                payload: queued_forward_payload,
                route: None,
                fault_continuation: Default::default(),
            },
            BackendNetworkOutput {
                source: destination.clone(),
                destination: source.clone(),
                emit_icount: Icount { retired: 8 },
                sequence: 3,
                payload: queued_reverse_payload,
                route: None,
                fault_continuation: Default::default(),
            },
        ];
        let append = interceptor
            .evaluate_boundary(
                FaultCoordinate {
                    virtual_nanos: 0,
                    retired_instructions: None,
                },
                &mut scheduler,
                &mut nodes,
                &mut pending_outputs,
            )
            .unwrap_or_else(|error| panic!("availability boundary should execute: {error}"));

        assert!(!append.entries.is_empty());
        assert_eq!(interceptor.transition_ledger.len(), 1);
        assert_eq!(interceptor.transition_ledger[0].in_flight.frame_count, 1);
        assert_eq!(interceptor.transition_ledger[0].queued.len(), 1);
        assert_eq!(
            interceptor.transition_ledger[0].old_state,
            NetworkAvailabilityState::Up
        );
        assert_eq!(pending_outputs.len(), 1);
        assert_eq!(pending_outputs[0].source, destination);
        assert_eq!(pending_outputs[0].destination, source);
        assert!(pending_outputs[0].route.is_some());
        let checkpoint = interceptor
            .checkpoint(&scheduler, &pending_outputs, &mut nodes)
            .unwrap_or_else(|error| panic!("network checkpoint should encode: {error}"));
        let mut divergent_pending = pending_outputs.clone();
        divergent_pending[0].payload.push(0xff);
        let divergent = interceptor
            .checkpoint(&scheduler, &divergent_pending, &mut nodes)
            .unwrap_or_else(|error| panic!("divergent checkpoint should encode: {error}"));
        assert_ne!(checkpoint.id(), divergent.id());
        let after = scheduler
            .drop_network_inflight_for_route(&source, &destination)
            .unwrap_or_else(|error| panic!("test route should remain valid: {error}"));
        assert_eq!(after.frame_count, 0);
    }

    #[test]
    fn production_resolve_availability_suppresses_the_routed_frame() {
        let (world, segment) = availability_world();
        let scenario = SchedulerLivenessScenario::from_runnable_world(
            "production-resolve-availability",
            Shift::default(),
            16,
            SimInstant { nanos: 128 },
            0,
            &world,
        );
        let mut scheduler = SingleScheduler::from_world(
            scenario,
            &world,
            &MemoryDagStore::new(),
            WorldIoLayoutPolicy::default(),
        )
        .unwrap_or_else(|error| panic!("test scheduler should build: {error}"));
        let mut nodes = ProductionNodeSet::new();
        let runtime = ProductionFaultRuntime::new(
            down_plan_at(segment, FaultPhase::Resolve),
            Some(Arc::new(NoArtifacts)),
            SignalBoundarySnapshot::default(),
            ContentHash::from_bytes(b"production-resolve-availability"),
            &nodes,
        )
        .unwrap_or_else(|error| panic!("test fault runtime should build: {error}"));
        let mut interceptor = ProductionFaultNetworkInterceptor::new(
            runtime,
            world.fault_topology().clone(),
            world.links().to_vec(),
        );
        let mut pending_outputs = Vec::new();
        interceptor
            .evaluate_boundary(
                FaultCoordinate {
                    virtual_nanos: 0,
                    retired_instructions: None,
                },
                &mut scheduler,
                &mut nodes,
                &mut pending_outputs,
            )
            .unwrap_or_else(|error| panic!("resolve availability should activate: {error}"));

        let source = crucible::NodeId {
            name: String::from("left"),
        };
        let destination = crucible::NodeId {
            name: String::from("right"),
        };
        let mut payload = vec![0_u8; 14];
        payload[..6].copy_from_slice(&deterministic_node_mac(&destination));
        let mut outputs = vec![BackendNetworkOutput {
            source,
            destination,
            emit_icount: Icount { retired: 0 },
            sequence: 1,
            payload,
            route: None,
            fault_continuation: Default::default(),
        }];
        interceptor
            .intercept_network_outputs(
                &mut scheduler,
                &mut nodes,
                VirtualTime { ticks: 0 },
                &mut pending_outputs,
                &mut outputs,
            )
            .unwrap_or_else(|error| panic!("resolve opportunity should execute: {error}"));
        assert!(outputs.is_empty());
    }

    #[test]
    fn production_preserve_keeps_queued_and_inflight_frames_on_the_old_profile() {
        let (world, segment) = availability_world();
        let scenario = SchedulerLivenessScenario::from_runnable_world(
            "production-preserve-availability",
            Shift::default(),
            16,
            SimInstant { nanos: 128 },
            0,
            &world,
        );
        let mut scheduler = SingleScheduler::from_world(
            scenario,
            &world,
            &MemoryDagStore::new(),
            WorldIoLayoutPolicy::default(),
        )
        .unwrap_or_else(|error| panic!("test scheduler should build: {error}"));
        let source = crucible::NodeId {
            name: String::from("left"),
        };
        let destination = crucible::NodeId {
            name: String::from("right"),
        };
        let mut payload = vec![0_u8; 14];
        payload[..6].copy_from_slice(&deterministic_node_mac(&destination));
        QuantumLoop::append_backend_network_outputs(
            &mut scheduler,
            vec![BackendNetworkOutput {
                source: source.clone(),
                destination: destination.clone(),
                emit_icount: Icount { retired: 0 },
                sequence: 1,
                payload: payload.clone(),
                route: None,
                fault_continuation: Default::default(),
            }],
        )
        .unwrap_or_else(|error| panic!("test frame should route: {error}"));

        let mut nodes = ProductionNodeSet::new();
        let runtime = ProductionFaultRuntime::new(
            down_plan_with_policies(
                segment,
                FaultPhase::Admit,
                NetworkInFlightPolicy::Preserve,
                NetworkInFlightPolicy::Preserve,
            ),
            Some(Arc::new(NoArtifacts)),
            SignalBoundarySnapshot::default(),
            ContentHash::from_bytes(b"production-preserve-availability"),
            &nodes,
        )
        .unwrap_or_else(|error| panic!("test fault runtime should build: {error}"));
        let mut interceptor = ProductionFaultNetworkInterceptor::new(
            runtime,
            world.fault_topology().clone(),
            world.links().to_vec(),
        );
        let mut pending_outputs = vec![BackendNetworkOutput {
            source: source.clone(),
            destination: destination.clone(),
            emit_icount: Icount { retired: 0 },
            sequence: 2,
            payload,
            route: None,
            fault_continuation: Default::default(),
        }];
        interceptor
            .evaluate_boundary(
                FaultCoordinate {
                    virtual_nanos: 0,
                    retired_instructions: None,
                },
                &mut scheduler,
                &mut nodes,
                &mut pending_outputs,
            )
            .unwrap_or_else(|error| panic!("preserve transition should execute: {error}"));

        assert_eq!(pending_outputs.len(), 1);
        assert!(
            pending_outputs[0]
                .fault_continuation
                .preserves_availability(&object_id("network-down-binding"), FaultPhase::Admit)
        );
        let preserved_inflight = scheduler
            .drop_network_inflight_for_route(&source, &destination)
            .unwrap_or_else(|error| panic!("preserved route should remain valid: {error}"));
        assert_eq!(preserved_inflight.frame_count, 1);
        let mut outputs = std::mem::take(&mut pending_outputs);
        interceptor
            .intercept_network_outputs(
                &mut scheduler,
                &mut nodes,
                VirtualTime { ticks: 0 },
                &mut pending_outputs,
                &mut outputs,
            )
            .unwrap_or_else(|error| panic!("preserved frame should bypass new outage: {error}"));
        assert_eq!(outputs.len(), 1);
    }
}
