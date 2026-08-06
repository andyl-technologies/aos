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

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct NetworkEffectStateKey {
    binding: FaultObjectId,
    target: crucible::model::ResolvedFaultTarget,
    effect: crucible::model::EffectKind,
}

impl NetworkEffectStateKey {
    fn from_action(action: &ResolvedBindingAction) -> Self {
        Self {
            binding: action.binding.clone(),
            target: action.target.clone(),
            effect: action.effect.kind(),
        }
    }
}

#[derive(Clone, Debug, Default)]
struct NetworkTokenBucketState {
    tokens_bits: u64,
    refill_remainder: u64,
    last_refill_nanos: u64,
    transition_sequence: u64,
}

#[derive(Clone, Debug)]
struct NetworkQueueReservation {
    enqueue_nanos: u64,
    finish_nanos: u64,
    bytes: u64,
    opportunity: ContentHash,
}

#[derive(Clone, Debug, Default)]
struct NetworkQueueState {
    service_cursor_nanos: u64,
    reservations: Vec<NetworkQueueReservation>,
}

#[derive(Clone, Debug, Default)]
struct NetworkEffectRuntimeState {
    token_buckets: BTreeMap<NetworkEffectStateKey, NetworkTokenBucketState>,
    queues: BTreeMap<crucible::model::ResolvedFaultTarget, NetworkQueueState>,
    burst_bad: BTreeMap<NetworkEffectStateKey, bool>,
    state_machines: BTreeMap<NetworkEffectStateKey, FaultObjectId>,
}

/// Owns the production signal continuation at the pre-routing network seam.
pub(super) struct ProductionFaultNetworkInterceptor {
    runtime: ProductionFaultRuntime,
    topology: crucible::model::WorldFaultTopology,
    links: Vec<crucible::LinkDef>,
    coordinate: Option<u64>,
    coordinate_sequence: u64,
    transition_ledger: Vec<NetworkAvailabilityTransitionRecord>,
    effect_state: NetworkEffectRuntimeState,
}

impl ProductionFaultNetworkInterceptor {
    /// Creates an interceptor around the admitted production continuation.
    #[must_use]
    pub(super) fn new(
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
            effect_state: NetworkEffectRuntimeState::default(),
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
        append_network_effect_state(&mut material, &self.effect_state)?;
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
        let cursor_before = (self.coordinate, self.coordinate_sequence);
        let sequence = self.next_sequence(coordinate.virtual_nanos)?;
        let mut staged_scheduler = scheduler.clone();
        let mut staged_pending = pending_outputs.clone();
        let host_before = self.runtime.host_state().clone();
        let mut evaluation = match self
            .runtime
            .evaluate_boundary(coordinate, sequence, backend)
        {
            Ok(evaluation) => evaluation,
            Err(error) => {
                (self.coordinate, self.coordinate_sequence) = cursor_before;
                return Err(SchedulerError::BoundaryViolation {
                    message: format!("signal fault boundary failed closed: {error}"),
                });
            }
        };
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
                matches!(
                    in_flight_policy,
                    NetworkInFlightPolicy::Drop | NetworkInFlightPolicy::TypedError
                )
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
                match queued_policy {
                    NetworkInFlightPolicy::Preserve => {
                        routed.fault_continuation.preserve_availability(
                            action.binding.clone(),
                            action.target.clone(),
                            action.phase,
                            action.transition_sequence,
                        )
                    }
                    NetworkInFlightPolicy::Reevaluate => {}
                    NetworkInFlightPolicy::Drop | NetworkInFlightPolicy::TypedError => {
                        destructive = true;
                    }
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
        append_evidence_bytes(material, preserved.target.canonical_material().as_bytes())?;
        append_evidence_bytes(material, preserved.phase.as_str().as_bytes())?;
        material.extend_from_slice(&preserved.transition_sequence.to_be_bytes());
    }
    let cursor = output.fault_continuation.cursor();
    material.extend_from_slice(&cursor.stage_index().to_be_bytes());
    material.push(cursor.phase_index());
    material.extend_from_slice(&cursor.not_before_nanos().to_be_bytes());
    material.extend_from_slice(&cursor.release_nanos().to_be_bytes());
    match cursor.queue_opportunity() {
        Some(opportunity) => {
            material.push(1);
            material.extend_from_slice(&opportunity.bytes);
        }
        None => material.push(0),
    }
    let effects = output.fault_continuation.resolved_frame_effects();
    material.extend_from_slice(&effects.latency_delta_nanos().to_be_bytes());
    material.extend_from_slice(&effects.additional_delay_nanos().to_be_bytes());
    material.push(u8::from(effects.is_dropped()));
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

fn append_network_effect_state(
    material: &mut Vec<u8>,
    state: &NetworkEffectRuntimeState,
) -> Result<(), SchedulerError> {
    append_evidence_count(material, state.token_buckets.len())?;
    for (key, bucket) in &state.token_buckets {
        append_network_effect_state_key(material, key)?;
        material.extend_from_slice(&bucket.tokens_bits.to_be_bytes());
        material.extend_from_slice(&bucket.refill_remainder.to_be_bytes());
        material.extend_from_slice(&bucket.last_refill_nanos.to_be_bytes());
        material.extend_from_slice(&bucket.transition_sequence.to_be_bytes());
    }
    append_evidence_count(material, state.queues.len())?;
    for (target, queue) in &state.queues {
        append_evidence_bytes(material, target.canonical_material().as_bytes())?;
        material.extend_from_slice(&queue.service_cursor_nanos.to_be_bytes());
        append_evidence_count(material, queue.reservations.len())?;
        for reservation in &queue.reservations {
            material.extend_from_slice(&reservation.enqueue_nanos.to_be_bytes());
            material.extend_from_slice(&reservation.finish_nanos.to_be_bytes());
            material.extend_from_slice(&reservation.bytes.to_be_bytes());
            material.extend_from_slice(&reservation.opportunity.bytes);
        }
    }
    append_evidence_count(material, state.burst_bad.len())?;
    for (key, bad) in &state.burst_bad {
        append_network_effect_state_key(material, key)?;
        material.push(u8::from(*bad));
    }
    append_evidence_count(material, state.state_machines.len())?;
    for (key, current) in &state.state_machines {
        append_network_effect_state_key(material, key)?;
        append_evidence_bytes(material, current.as_str().as_bytes())?;
    }
    Ok(())
}

fn append_network_effect_state_key(
    material: &mut Vec<u8>,
    key: &NetworkEffectStateKey,
) -> Result<(), SchedulerError> {
    append_evidence_bytes(material, key.binding.as_str().as_bytes())?;
    append_evidence_bytes(material, key.target.canonical_material().as_bytes())?;
    append_evidence_bytes(material, key.effect.as_str().as_bytes())
}

fn append_evidence_count(material: &mut Vec<u8>, count: usize) -> Result<(), SchedulerError> {
    let count = u64::try_from(count).map_err(|_error| SchedulerError::BoundaryViolation {
        message: String::from("network effect-state collection exceeds the canonical width"),
    })?;
    material.extend_from_slice(&count.to_be_bytes());
    Ok(())
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
                    let resume_stage = usize::try_from(
                        output.fault_continuation.cursor().stage_index(),
                    )
                    .map_err(|_error| SchedulerError::BoundaryViolation {
                        message: String::from("network route stage exceeds host width"),
                    })?;
                    if resume_stage > stages.len() {
                        return Err(SchedulerError::BoundaryViolation {
                            message: format!(
                                "network frame {} resumes after the end of its route",
                                output.sequence
                            ),
                        });
                    }
                    for (stage_index, stage) in stages.iter().enumerate().skip(resume_stage) {
                        let resume_phase = if stage_index == resume_stage {
                            usize::from(output.fault_continuation.cursor().phase_index())
                        } else {
                            0
                        };
                        if resume_phase > stage.phases().len() {
                            return Err(SchedulerError::BoundaryViolation {
                                message: format!(
                                    "network frame {} resumes after the end of route stage {stage_index}",
                                    output.sequence
                                ),
                            });
                        }
                        for phase in stage.phases().iter().copied().skip(resume_phase) {
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
                                producer_sequence: output.sequence,
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
                            let deferred_until = if !frame_actions.is_empty() {
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
                                None
                            };
                            output
                                .fault_continuation
                                .cursor_mut()
                                .advance(stage.phases().len())
                                .map_err(|error| SchedulerError::BoundaryViolation {
                                    message: format!(
                                        "network fault continuation cursor failed: {error}"
                                    ),
                                })?;
                            if let Some(not_before_nanos) = deferred_until {
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
                                next_wakeup_nanos =
                                    earliest_wakeup(next_wakeup_nanos, Some(not_before_nanos));
                                staged_pending.push(output);
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
) -> Result<Option<u64>, SchedulerError> {
    let mut deferred_until = None;
    let mut queue_policy = None;
    for action in actions {
        let EffectSpecification::Network(specification) = action.effect.specification() else {
            return Err(network_effect_application_error(
                action,
                "non-network effect reached the network adapter",
            ));
        };
        match specification {
            NetworkEffectSpecification::ServiceCurve { segments } => {
                let elapsed = opportunity
                    .coordinate()
                    .virtual_nanos
                    .checked_sub(action.coordinate.virtual_nanos)
                    .ok_or_else(|| {
                        network_effect_application_error(
                            action,
                            "service-curve activation follows its opportunity",
                        )
                    })?;
                let segment = segments
                    .as_slice()
                    .iter()
                    .rev()
                    .find(|segment| segment.at_nanos <= elapsed)
                    .ok_or_else(|| {
                        network_effect_application_error(
                            action,
                            "service curve has no segment at its activation coordinate",
                        )
                    })?;
                effects
                    .constrain_rate(segment.rate_bps.get())
                    .map_err(|error| {
                        network_effect_application_error(action, &error.to_string())
                    })?;
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
            NetworkEffectSpecification::QueuePolicy { .. } => {
                if queue_policy.replace((action, specification)).is_some() {
                    return Err(network_effect_application_error(
                        action,
                        "multiple queue policies survived conflict composition",
                    ));
                }
            }
            _ => apply_network_frame_action(
                payload,
                effects,
                action,
                opportunity,
                scenario_seed,
                topology,
            )?,
        }
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
        let service_nanos = service_rate
            .map(|rate| network_serialization_nanos(payload.len(), rate, action))
            .transpose()?
            .unwrap_or(0);
        let release = apply_network_queue_policy(
            state,
            pending_outputs,
            effects,
            action,
            opportunity,
            scenario_seed,
            topology,
            payload.len(),
            capacity_bytes.get(),
            u64::from(capacity_frames.get()),
            *discipline,
            discipline_parameters.as_ref(),
            *overflow,
            service_nanos,
            deferred_until,
        )?;
        deferred_until = latest_wakeup(deferred_until, release);
    }
    Ok(deferred_until.filter(|coordinate| *coordinate > opportunity.coordinate().virtual_nanos))
}

fn network_serialization_nanos(
    payload_bytes: usize,
    rate_bps: u64,
    action: &ResolvedBindingAction,
) -> Result<u64, SchedulerError> {
    let bits = u128::try_from(payload_bytes)
        .ok()
        .and_then(|bytes| bytes.checked_mul(8))
        .ok_or_else(|| network_effect_application_error(action, "frame bit length overflowed"))?;
    ceil_ratio_u128(
        bits.checked_mul(1_000_000_000).ok_or_else(|| {
            network_effect_application_error(action, "serialization interval overflowed")
        })?,
        u128::from(rate_bps),
    )
    .and_then(|value| u64::try_from(value).ok())
    .ok_or_else(|| network_effect_application_error(action, "serialization interval exceeds u64"))
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
    payload_bytes: usize,
    capacity_bytes: u64,
    capacity_frames: u64,
    discipline: crucible::model::NetworkQueueDiscipline,
    discipline_parameters: Option<&FaultObjectId>,
    overflow: crucible::model::NetworkQueueOverflow,
    service_nanos: u64,
    prerequisite_release: Option<u64>,
) -> Result<Option<u64>, SchedulerError> {
    let now = opportunity.coordinate().virtual_nanos;
    let payload_bytes = u64::try_from(payload_bytes).map_err(|_error| {
        network_effect_application_error(action, "frame byte length exceeds queue width")
    })?;
    let queue = state.queues.entry(action.target.clone()).or_default();
    queue
        .reservations
        .retain(|reservation| reservation.finish_nanos > now);
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
    let mut overflowed = occupied_bytes
        .checked_add(payload_bytes)
        .is_none_or(|bytes| bytes > capacity_bytes)
        || occupied_frames
            .checked_add(1)
            .is_none_or(|frames| frames > capacity_frames);

    if discipline == crucible::model::NetworkQueueDiscipline::Red {
        let parameters = network_queue_discipline(topology, discipline_parameters, action)?;
        let minimum = parameters.red_minimum_bytes.ok_or_else(|| {
            network_effect_application_error(action, "RED policy omitted its minimum threshold")
        })?;
        let maximum = parameters.red_maximum_bytes.ok_or_else(|| {
            network_effect_application_error(action, "RED policy omitted its maximum threshold")
        })?;
        let maximum_probability = parameters.red_maximum_probability.ok_or_else(|| {
            network_effect_application_error(action, "RED policy omitted its maximum probability")
        })?;
        let probability = if occupied_bytes <= minimum {
            0
        } else if occupied_bytes >= maximum {
            maximum_probability.get()
        } else {
            let width = maximum - minimum;
            let offset = occupied_bytes - minimum;
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
        overflowed |= probability_fires(
            probability,
            network_effect_draw(scenario_seed, opportunity, action, "queue-red", 0),
        );
    } else if discipline_parameters.is_some() {
        let _parameters = network_queue_discipline(topology, discipline_parameters, action)?;
    }

    if overflowed {
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
                if queue.reservations.is_empty() {
                    effects.mark_drop();
                } else {
                    let victim = if overflow == crucible::model::NetworkQueueOverflow::HeadDrop {
                        0
                    } else {
                        usize::try_from(
                            network_effect_draw(
                                scenario_seed,
                                opportunity,
                                action,
                                "queue-victim",
                                0,
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
                }
            }
        }
    }
    if effects.is_dropped() || service_nanos == 0 {
        return Ok(None);
    }
    let start = queue
        .service_cursor_nanos
        .max(prerequisite_release.unwrap_or(now));
    let finish = start.checked_add(service_nanos).ok_or_else(|| {
        network_effect_application_error(action, "queue service coordinate overflowed")
    })?;
    queue.service_cursor_nanos = finish;
    queue.reservations.push(NetworkQueueReservation {
        enqueue_nanos: now,
        finish_nanos: finish,
        bytes: payload_bytes,
        opportunity: opportunity.id(),
    });
    queue
        .reservations
        .sort_by_key(|reservation| (reservation.enqueue_nanos, reservation.opportunity));
    Ok(Some(finish))
}

fn network_queue_discipline<'a>(
    topology: &'a crucible::model::WorldFaultTopology,
    reference: Option<&FaultObjectId>,
    action: &ResolvedBindingAction,
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
    let key = NetworkEffectStateKey::from_action(action);
    let bucket = state
        .token_buckets
        .entry(key)
        .or_insert_with(|| NetworkTokenBucketState {
            tokens_bits: initial_bits,
            refill_remainder: 0,
            last_refill_nanos: action.coordinate.virtual_nanos,
            transition_sequence: action.transition_sequence,
        });
    if bucket.transition_sequence != action.transition_sequence {
        *bucket = NetworkTokenBucketState {
            tokens_bits: initial_bits,
            refill_remainder: 0,
            last_refill_nanos: action.coordinate.virtual_nanos,
            transition_sequence: action.transition_sequence,
        };
    }
    if now < bucket.last_refill_nanos {
        let queued_delay = bucket.last_refill_nanos - now;
        let service_delay = ceil_ratio_u128(
            u128::from(payload_bits)
                .checked_mul(1_000_000_000)
                .ok_or_else(|| network_effect_application_error(action, "token wait overflowed"))?,
            u128::from(rate_bps),
        )
        .and_then(|value| u64::try_from(value).ok())
        .ok_or_else(|| network_effect_application_error(action, "token wait exceeds u64"))?;
        bucket.last_refill_nanos = bucket
            .last_refill_nanos
            .checked_add(service_delay)
            .ok_or_else(|| network_effect_application_error(action, "token release overflowed"))?;
        bucket.tokens_bits = 0;
        bucket.refill_remainder = 0;
        return queued_delay
            .checked_add(service_delay)
            .ok_or_else(|| network_effect_application_error(action, "token delay overflowed"));
    }
    let elapsed = now - bucket.last_refill_nanos;
    let numerator = u128::from(elapsed)
        .checked_mul(u128::from(rate_bps))
        .and_then(|value| value.checked_add(u128::from(bucket.refill_remainder)))
        .ok_or_else(|| network_effect_application_error(action, "token refill overflowed"))?;
    let added = numerator / 1_000_000_000;
    bucket.refill_remainder = u64::try_from(numerator % 1_000_000_000).map_err(|_error| {
        network_effect_application_error(action, "token refill remainder overflowed")
    })?;
    bucket.tokens_bits = u64::try_from(
        u128::from(bucket.tokens_bits)
            .saturating_add(added)
            .min(u128::from(burst_bits)),
    )
    .map_err(|_error| network_effect_application_error(action, "token balance overflowed"))?;
    bucket.last_refill_nanos = now;
    if bucket.tokens_bits >= payload_bits {
        bucket.tokens_bits -= payload_bits;
        return Ok(0);
    }
    let deficit = payload_bits - bucket.tokens_bits;
    let delay = ceil_ratio_u128(
        u128::from(deficit)
            .checked_mul(1_000_000_000)
            .ok_or_else(|| network_effect_application_error(action, "token wait overflowed"))?,
        u128::from(rate_bps),
    )
    .and_then(|value| u64::try_from(value).ok())
    .ok_or_else(|| network_effect_application_error(action, "token wait exceeds u64"))?;
    bucket.tokens_bits = 0;
    bucket.refill_remainder = 0;
    bucket.last_refill_nanos = now
        .checked_add(delay)
        .ok_or_else(|| network_effect_application_error(action, "token release overflowed"))?;
    Ok(delay)
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
    let crucible::model::NetworkPolicyArtifactKind::ErrorStateTable { states, .. } =
        &declaration.artifact
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
    let bad = state.burst_bad.entry(key).or_default();
    let transition = if *bad { bad_to_good } else { good_to_bad };
    if probability_fires(
        transition,
        network_effect_draw(scenario_seed, opportunity, action, "burst-transition", 0),
    ) {
        *bad = !*bad;
    }
    let selected = &states[usize::from(*bad)];
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
        let draw = network_effect_draw(
            scenario_seed,
            opportunity,
            action,
            "burst-corruption-bit",
            0,
        );
        let bit_count = payload.len().checked_mul(8).ok_or_else(|| {
            network_effect_application_error(action, "corruption bit count overflowed")
        })?;
        let bit = usize::try_from(
            draw % u64::try_from(bit_count).map_err(|_error| {
                network_effect_application_error(action, "corruption bit count exceeds u64")
            })?,
        )
        .map_err(|_error| {
            network_effect_application_error(action, "corruption bit exceeds host")
        })?;
        payload[bit / 8] ^= 1_u8 << (bit % 8);
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
            let input = mapped_network_integer(action)?;
            for (reference, axis) in [
                (loss_hazard.as_ref(), "profile-loss"),
                (corruption_hazard.as_ref(), "profile-corruption"),
            ] {
                if let Some(reference) = reference {
                    let probability = network_policy_lookup(topology, reference, input)?;
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
                let latency = network_policy_lookup(topology, reference, input)?;
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
        NetworkEffectSpecification::Mtu {
            mtu_bytes,
            oversize: crucible::model::NetworkOversizeDisposition::Drop,
        } if payload.len() > usize::try_from(mtu_bytes.get()).unwrap_or(usize::MAX) => {
            effects.mark_drop();
        }
        NetworkEffectSpecification::Mtu { .. } => {}
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
        NetworkEffectSpecification::Flap { .. }
        | NetworkEffectSpecification::NegotiatedMode { .. }
        | NetworkEffectSpecification::PropagationDelay { .. }
        | NetworkEffectSpecification::Jitter { .. }
        | NetworkEffectSpecification::ServiceCurve { .. }
        | NetworkEffectSpecification::TokenBucket { .. }
        | NetworkEffectSpecification::QueuePolicy { .. }
        | NetworkEffectSpecification::BurstErrorState { .. }
        | NetworkEffectSpecification::DetectedFrameError { .. }
        | NetworkEffectSpecification::PauseBackpressure { .. }
        | NetworkEffectSpecification::RecipientSubset { .. }
        | NetworkEffectSpecification::ForwarderLifecycle { .. }
        | NetworkEffectSpecification::ForwardingMutation { .. }
        | NetworkEffectSpecification::RouteTransition { .. }
        | NetworkEffectSpecification::ControlPlaneService { .. }
        | NetworkEffectSpecification::FirewallDisposition { .. }
        | NetworkEffectSpecification::ConnectionState { .. }
        | NetworkEffectSpecification::SharedMedium { .. }
        | NetworkEffectSpecification::RfChannel { .. }
        | NetworkEffectSpecification::Association { .. }
        | NetworkEffectSpecification::ControlResultTransform { .. }
        | NetworkEffectSpecification::Contact { .. }
        | NetworkEffectSpecification::CustodyQueue { .. } => {
            return Err(network_effect_application_error(
                action,
                "effect requires network phase state that is not yet present",
            ));
        }
    }
    Ok(())
}

fn network_effect_application_error(
    action: &ResolvedBindingAction,
    reason: &str,
) -> SchedulerError {
    SchedulerError::BoundaryViolation {
        message: format!(
            "apply network effect `{}` from binding `{}`: {reason}",
            action.effect.kind().as_str(),
            action.binding
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

fn mapped_network_integer(action: &ResolvedBindingAction) -> Result<i64, SchedulerError> {
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
    let value = values.first().ok_or_else(|| {
        network_effect_application_error(action, "network lookup has no numeric input")
    })?;
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
    let insertion = table.points.partition_point(|point| point.input <= input);
    if insertion == 0 {
        return match table.outside {
            crucible::model::NetworkPolicyOutsideRange::Clamp => Ok(table.points[0].output),
            crucible::model::NetworkPolicyOutsideRange::TypedError => {
                Err(SchedulerError::BoundaryViolation {
                    message: format!(
                        "network policy `{reference}` input {input} precedes its domain"
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
            message: format!("network policy `{reference}` input {input} follows its domain"),
        });
    };
    match table.interpolation {
        crucible::model::NetworkPolicyInterpolation::Step => Ok(lower.output),
        crucible::model::NetworkPolicyInterpolation::LinearTiesToEven => {
            interpolate_network_policy(lower, upper, input).ok_or_else(|| {
                SchedulerError::BoundaryViolation {
                    message: format!("network policy `{reference}` interpolation overflowed"),
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
        let preserved = &pending_outputs[0]
            .fault_continuation
            .preserved_availability()[0];
        assert_eq!(preserved.binding, object_id("network-down-binding"));
        assert!(
            pending_outputs[0]
                .fault_continuation
                .preserves_availability(
                    &preserved.binding,
                    &preserved.target,
                    preserved.phase,
                    preserved.transition_sequence,
                )
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

    #[test]
    fn production_reevaluate_retains_work_until_the_next_declared_phase() {
        let (world, segment) = availability_world();
        let scenario = SchedulerLivenessScenario::from_runnable_world(
            "production-reevaluate-availability",
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
                NetworkInFlightPolicy::Reevaluate,
                NetworkInFlightPolicy::Reevaluate,
            ),
            Some(Arc::new(NoArtifacts)),
            SignalBoundarySnapshot::default(),
            ContentHash::from_bytes(b"production-reevaluate-availability"),
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
            .unwrap_or_else(|error| panic!("reevaluate transition should execute: {error}"));

        assert_eq!(pending_outputs.len(), 1);
        assert!(
            pending_outputs[0]
                .fault_continuation
                .preserved_availability()
                .is_empty()
        );
        let retained_inflight = scheduler
            .drop_network_inflight_for_route(&source, &destination)
            .unwrap_or_else(|error| panic!("resolved route should remain valid: {error}"));
        assert_eq!(retained_inflight.frame_count, 1);

        let mut outputs = std::mem::take(&mut pending_outputs);
        interceptor
            .intercept_network_outputs(
                &mut scheduler,
                &mut nodes,
                VirtualTime { ticks: 0 },
                &mut pending_outputs,
                &mut outputs,
            )
            .unwrap_or_else(|error| panic!("reevaluated frame should execute: {error}"));
        assert!(outputs.is_empty());
    }
}
