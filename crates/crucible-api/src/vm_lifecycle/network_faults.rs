//! Production ownership of signal-driven network interception.
//!
//! The interceptor lives inside the backend quantum loop so committed QEMU
//! frames cannot bypass the exact pre-routing fault boundary. The executable
//! network adapter is layered onto this owner; the runtime itself is never
//! shared through a test-only or process-global side channel.

mod boundary;
mod route;

use route::{availability_allows, earliest_wakeup, network_effect_application_error};

use std::collections::BTreeSet;

use super::*;
use crucible::model::{
    BindingActionKind, ContentHash, EffectSpecification, FAULT_RUNTIME_STATE_VERSION,
    FaultObjectId, FaultObservation, FaultObservationKind, FaultOpportunity, FaultPhase,
    NetworkAvailabilityState, NetworkEffectSpecification, NetworkInFlightPolicy,
    OpportunityPayload, ResolvedBindingAction,
};
use crucible::{BackendNetworkOutputInterceptor, SchedulerEventLogAppend};

const HARD_PENDING_NETWORK_FRAMES: usize = 65_536;
const HARD_PENDING_NETWORK_BYTES: usize = 1_073_741_824;

fn stage_pending_network_output(
    pending: &mut Vec<crucible::BackendNetworkOutput>,
    output: crucible::BackendNetworkOutput,
) -> Result<(), SchedulerError> {
    if output.fault_continuation.protocol_expansion_path().len()
        > crucible::model::HARD_NETWORK_PROTOCOL_EXPANSION_DEPTH
    {
        return Err(SchedulerError::BoundaryViolation {
            message: format!(
                "network protocol-expansion depth exceeds hard bound {}",
                crucible::model::HARD_NETWORK_PROTOCOL_EXPANSION_DEPTH
            ),
        });
    }
    if pending.len() == HARD_PENDING_NETWORK_FRAMES {
        return Err(SchedulerError::BoundaryViolation {
            message: format!(
                "signal-driven pending network frame count exceeds hard bound {HARD_PENDING_NETWORK_FRAMES}"
            ),
        });
    }
    let occupied = pending.iter().try_fold(0_usize, |total, queued| {
        total.checked_add(queued.payload.len())
    });
    let required = occupied.and_then(|total| total.checked_add(output.payload.len()));
    if required.is_none_or(|bytes| bytes > HARD_PENDING_NETWORK_BYTES) {
        return Err(SchedulerError::BoundaryViolation {
            message: format!(
                "signal-driven pending network bytes exceed hard bound {HARD_PENDING_NETWORK_BYTES}"
            ),
        });
    }
    pending.push(output);
    Ok(())
}

fn validate_pending_network_outputs(
    pending: &[crucible::BackendNetworkOutput],
) -> Result<(), SchedulerError> {
    if pending.len() > HARD_PENDING_NETWORK_FRAMES {
        return Err(SchedulerError::BoundaryViolation {
            message: format!(
                "restored pending network frame count exceeds hard bound {HARD_PENDING_NETWORK_FRAMES}"
            ),
        });
    }
    if pending.iter().any(|output| {
        output.fault_continuation.protocol_expansion_path().len()
            > crucible::model::HARD_NETWORK_PROTOCOL_EXPANSION_DEPTH
    }) {
        return Err(SchedulerError::BoundaryViolation {
            message: format!(
                "restored network protocol-expansion depth exceeds hard bound {}",
                crucible::model::HARD_NETWORK_PROTOCOL_EXPANSION_DEPTH
            ),
        });
    }
    let bytes = pending.iter().try_fold(0_usize, |total, output| {
        total.checked_add(output.payload.len())
    });
    if bytes.is_none_or(|bytes| bytes > HARD_PENDING_NETWORK_BYTES) {
        return Err(SchedulerError::BoundaryViolation {
            message: format!(
                "restored pending network bytes exceed hard bound {HARD_PENDING_NETWORK_BYTES}"
            ),
        });
    }
    Ok(())
}

fn validate_network_adapter_checkpoint(
    checkpoint: &NetworkAdapterCheckpoint,
) -> Result<(), SchedulerError> {
    if checkpoint.semantic_version != FAULT_RUNTIME_STATE_VERSION
        || checkpoint.coordinate.is_none() && checkpoint.coordinate_sequence != 0
        || checkpoint.effect_state.token_buckets.len() > 65_536
        || checkpoint.effect_state.queues.len() > 65_536
        || checkpoint.effect_state.burst_states.len() > 65_536
        || checkpoint.effect_state.state_machines.len() > 65_536
        || checkpoint.effect_state.backpressure.len() > 65_536
    {
        return Err(SchedulerError::BoundaryViolation {
            message: String::from(
                "network adapter checkpoint schema or top-level bounds are invalid",
            ),
        });
    }
    for (target, queue) in &checkpoint.effect_state.queues {
        if queue.reservations.len() > HARD_PENDING_NETWORK_FRAMES
            || queue.served_frames_by_class.len() > 65_536
            || queue.served_bytes_by_class.len() > 65_536
            || queue.reservations.iter().any(|reservation| {
                reservation.service_curves.len() > 65_536
                    || reservation.base_ready_nanos > reservation.ready_nanos
                    || reservation.ready_nanos > reservation.service_start_nanos
                    || reservation.service_start_nanos > reservation.finish_nanos
                    || reservation
                        .bytes
                        .checked_mul(8)
                        .is_none_or(|bits| bits != reservation.payload_bits)
                    || reservation.remaining_nano_bits == 0
                    || u128::from(reservation.payload_bits)
                        .checked_mul(1_000_000_000)
                        .is_none_or(|demand| reservation.remaining_nano_bits > demand)
                    || reservation
                        .service_curves
                        .iter()
                        .any(|curve| curve.segments.is_empty() || curve.segments.len() > 65_536)
            })
        {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from("network adapter queue checkpoint exceeds hard bounds"),
            });
        }
        if queue.configuration.is_none() && !queue.reservations.is_empty() {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from("network queue checkpoint omitted its configuration"),
            });
        }
        if let Some(configuration) = &queue.configuration {
            let parameters_required = !matches!(
                configuration.discipline,
                crucible::model::NetworkQueueDiscipline::Fifo
            );
            if &configuration.owner.target != target
                || !matches!(
                    configuration.owner.effect,
                    crucible::model::EffectKind::NetworkQueuePolicy
                        | crucible::model::EffectKind::NetworkServiceCurve
                )
                || parameters_required != configuration.discipline_parameters.is_some()
            {
                return Err(SchedulerError::BoundaryViolation {
                    message: String::from("network queue checkpoint configuration is invalid"),
                });
            }
        }
        let mut opportunities = BTreeSet::new();
        if queue
            .reservations
            .iter()
            .any(|reservation| !opportunities.insert(reservation.opportunity))
            || queue
                .reservations
                .windows(2)
                .any(|pair| pair[0].finish_nanos > pair[1].service_start_nanos)
        {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from("network queue checkpoint schedule overlaps or repeats"),
            });
        }
    }
    if checkpoint
        .effect_state
        .backpressure
        .iter()
        .any(|(key, pause)| {
            key.effect != crucible::model::EffectKind::NetworkPauseBackpressure
                || pause.class.as_str().is_empty()
        })
    {
        return Err(SchedulerError::BoundaryViolation {
            message: String::from("network backpressure checkpoint is invalid"),
        });
    }
    checkpoint.effect_state.boundary.validate_bounds()
}

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

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
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

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
struct NetworkTokenBucketState {
    tokens_nano_bits: u128,
    last_refill_nanos: u64,
    transition_sequence: u64,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct NetworkQueueReservation {
    enqueue_nanos: u64,
    base_ready_nanos: u64,
    ready_nanos: u64,
    service_start_nanos: u64,
    finish_nanos: u64,
    bytes: u64,
    payload_bits: u64,
    remaining_nano_bits: u128,
    base_rate_bps: Option<u64>,
    service_curves: Vec<NetworkServiceCurveState>,
    class: Option<FaultObjectId>,
    opportunity: ContentHash,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct NetworkServiceCurveState {
    activation_nanos: u64,
    segments: Vec<crucible::model::NetworkServiceSegment>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct NetworkQueueConfiguration {
    owner: NetworkEffectStateKey,
    discipline: crucible::model::NetworkQueueDiscipline,
    discipline_parameters: Option<FaultObjectId>,
}

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
struct NetworkQueueState {
    configuration: Option<NetworkQueueConfiguration>,
    service_cursor_nanos: u64,
    reservations: Vec<NetworkQueueReservation>,
    served_frames_by_class: BTreeMap<FaultObjectId, u64>,
    served_bytes_by_class: BTreeMap<FaultObjectId, u64>,
    red_average_bytes_q32: u128,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct NetworkPauseState {
    class: FaultObjectId,
    paused_until: Option<u64>,
    transition_sequence: u64,
}

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
struct NetworkEffectRuntimeState {
    token_buckets: BTreeMap<NetworkEffectStateKey, NetworkTokenBucketState>,
    queues: BTreeMap<crucible::model::ResolvedFaultTarget, NetworkQueueState>,
    burst_states: BTreeMap<NetworkEffectStateKey, FaultObjectId>,
    state_machines: BTreeMap<NetworkEffectStateKey, FaultObjectId>,
    backpressure: BTreeMap<NetworkEffectStateKey, NetworkPauseState>,
    boundary: boundary::BoundaryNetworkState,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct NetworkAdapterCheckpoint {
    semantic_version: u16,
    coordinate: Option<u64>,
    coordinate_sequence: u64,
    effect_state: NetworkEffectRuntimeState,
}

struct StagedNetworkRestore {
    scheduler: SingleScheduler,
    pending_outputs: Vec<crucible::BackendNetworkOutput>,
    adapter: NetworkAdapterCheckpoint,
    identity: ContentHash,
}

fn stage_network_restore(
    checkpoint: &ProductionFaultRuntimeCheckpoint,
    scheduler: &SingleScheduler,
) -> Result<StagedNetworkRestore, SchedulerError> {
    let network =
        checkpoint
            .network_state()
            .cloned()
            .ok_or_else(|| SchedulerError::BoundaryViolation {
                message: String::from(
                    "restored production fault runtime omitted its network continuation",
                ),
            })?;
    let (scheduler_state, pending_outputs, adapter_bytes, identity) = network.into_parts();
    validate_pending_network_outputs(&pending_outputs)?;
    let adapter: NetworkAdapterCheckpoint =
        serde_json::from_slice(&adapter_bytes).map_err(|error| {
            SchedulerError::BoundaryViolation {
                message: format!("decode production network adapter checkpoint: {error}"),
            }
        })?;
    validate_network_adapter_checkpoint(&adapter)?;
    let mut staged_scheduler = scheduler.clone();
    staged_scheduler.restore_network_checkpoint(&scheduler_state)?;
    let actual = network_state_digest_from_parts(
        &staged_scheduler,
        &pending_outputs,
        adapter.coordinate,
        adapter.coordinate_sequence,
        &adapter.effect_state,
    )?;
    if actual != identity {
        return Err(SchedulerError::BoundaryViolation {
            message: format!(
                "restored network continuation identity {}, expected {}",
                actual.to_hex(),
                identity.to_hex()
            ),
        });
    }
    Ok(StagedNetworkRestore {
        scheduler: staged_scheduler,
        pending_outputs,
        adapter,
        identity,
    })
}

fn network_state_digest_from_parts(
    scheduler: &SingleScheduler,
    pending_outputs: &[crucible::BackendNetworkOutput],
    coordinate: Option<u64>,
    coordinate_sequence: u64,
    effect_state: &NetworkEffectRuntimeState,
) -> Result<ContentHash, SchedulerError> {
    let mut material = Vec::new();
    material.extend_from_slice(&scheduler.network_continuation_digest()?.bytes);
    material.extend_from_slice(&coordinate.unwrap_or(u64::MAX).to_be_bytes());
    material.extend_from_slice(&coordinate_sequence.to_be_bytes());
    let pending_count = u64::try_from(pending_outputs.len()).map_err(|_error| {
        SchedulerError::BoundaryViolation {
            message: String::from("pending network output count exceeds the checkpoint width"),
        }
    })?;
    material.extend_from_slice(&pending_count.to_be_bytes());
    for output in pending_outputs {
        append_backend_output_evidence(&mut material, output)?;
    }
    append_network_effect_state(&mut material, effect_state)?;
    Ok(ContentHash::from_bytes(&material))
}

/// Owns the production signal continuation at the pre-routing network seam.
pub(super) struct ProductionFaultNetworkInterceptor {
    runtime: ProductionFaultRuntime,
    topology: crucible::model::WorldFaultTopology,
    links: Vec<crucible::LinkDef>,
    coordinate: Option<u64>,
    coordinate_sequence: u64,
    transition_ledger: BTreeMap<ContentHash, NetworkAvailabilityTransitionRecord>,
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
            transition_ledger: BTreeMap::new(),
            effect_state: NetworkEffectRuntimeState::default(),
        }
    }

    /// Restores an authenticated adapter, scheduler, and pending-frame continuation.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when the runtime has no paired network state,
    /// its schema/bounds are invalid, scheduler restoration fails, or the
    /// independently recomputed continuation identity differs.
    pub(super) fn restore(
        plan: crucible::model::FaultSignalPlan,
        artifacts: Option<Arc<dyn SignalArtifactProvider>>,
        scenario_seed: ContentHash,
        checkpoint: ProductionFaultRuntimeCheckpoint,
        nodes: &mut ProductionNodeSet,
        topology: crucible::model::WorldFaultTopology,
        links: Vec<crucible::LinkDef>,
        scheduler: &mut SingleScheduler,
        pending_outputs: &mut Vec<crucible::BackendNetworkOutput>,
    ) -> Result<Self, SchedulerError> {
        let staged = stage_network_restore(&checkpoint, scheduler)?;
        let mut runtime =
            ProductionFaultRuntime::restore(plan, artifacts, scenario_seed, checkpoint, nodes)
                .map_err(|error| SchedulerError::BoundaryViolation {
                    message: format!("restore production signal fault continuation: {error}"),
                })?;
        let authenticated = runtime.take_restored_network_state().ok_or_else(|| {
            SchedulerError::BoundaryViolation {
                message: String::from(
                    "authenticated production fault runtime lost its network continuation",
                ),
            }
        })?;
        if authenticated.id() != staged.identity {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from(
                    "production fault and staged network continuation identities differ",
                ),
            });
        }
        let restored = Self {
            runtime,
            topology,
            links,
            coordinate: staged.adapter.coordinate,
            coordinate_sequence: staged.adapter.coordinate_sequence,
            transition_ledger: BTreeMap::new(),
            effect_state: staged.adapter.effect_state,
        };
        *scheduler = staged.scheduler;
        *pending_outputs = staged.pending_outputs;
        Ok(restored)
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
        let adapter_state = serde_json::to_vec(&NetworkAdapterCheckpoint {
            semantic_version: FAULT_RUNTIME_STATE_VERSION,
            coordinate: self.coordinate,
            coordinate_sequence: self.coordinate_sequence,
            effect_state: self.effect_state.clone(),
        })
        .map_err(|error| SchedulerError::BoundaryViolation {
            message: format!("encode production network adapter checkpoint: {error}"),
        })?;
        let network_checkpoint = ProductionNetworkStateCheckpoint::new(
            network_state,
            scheduler.network_checkpoint(),
            pending_outputs.to_vec(),
            adapter_state,
        );
        self.runtime
            .checkpoint_with_network_state(backend, network_checkpoint)
            .map_err(|error| SchedulerError::BoundaryViolation {
                message: format!("capture production fault continuation: {error}"),
            })
    }

    fn network_state_digest(
        &self,
        scheduler: &SingleScheduler,
        pending_outputs: &[crucible::BackendNetworkOutput],
    ) -> Result<ContentHash, SchedulerError> {
        network_state_digest_from_parts(
            scheduler,
            pending_outputs,
            self.coordinate,
            self.coordinate_sequence,
            &self.effect_state,
        )
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
        let mut staged_effect_state = self.effect_state.clone();
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
            if impulses
                .iter()
                .any(|action| action.phase != FaultPhase::Boundary)
            {
                return Err(SchedulerError::BoundaryViolation {
                    message: String::from("network boundary produced a non-boundary impulse"),
                });
            }
            let boundary_actions = evaluation
                .actions
                .iter()
                .filter(|action| action.phase == FaultPhase::Boundary)
                .cloned()
                .chain(impulses)
                .collect::<Vec<_>>();
            let boundary_application = staged_effect_state.boundary.apply_actions(
                coordinate,
                boundary_actions,
                &self.topology,
            )?;
            for target in boundary_application.clear_queued_targets {
                if let Some(queue) = staged_effect_state.queues.remove(&target) {
                    let removed = queue
                        .reservations
                        .into_iter()
                        .map(|reservation| reservation.opportunity)
                        .collect::<BTreeSet<_>>();
                    staged_pending.retain(|output| {
                        output
                            .fault_continuation
                            .cursor()
                            .queue_opportunity()
                            .is_none_or(|opportunity| !removed.contains(&opportunity))
                    });
                }
            }
            let mut removed_route_opportunities = BTreeSet::new();
            for transition in &boundary_application.route_transitions {
                staged_pending.retain_mut(|output| {
                    if output.fault_continuation.cursor().route_path_version()
                        != Some(&transition.old_route)
                    {
                        return true;
                    }
                    match transition.policy {
                        NetworkInFlightPolicy::Preserve => true,
                        NetworkInFlightPolicy::Reevaluate => {
                            output
                                .fault_continuation
                                .cursor_mut()
                                .reevaluate_route_path();
                            true
                        }
                        NetworkInFlightPolicy::Drop | NetworkInFlightPolicy::TypedError => {
                            if let Some(opportunity) =
                                output.fault_continuation.cursor().queue_opportunity()
                            {
                                removed_route_opportunities.insert(opportunity);
                            }
                            false
                        }
                    }
                });
                if matches!(
                    transition.policy,
                    NetworkInFlightPolicy::Drop | NetworkInFlightPolicy::TypedError
                ) {
                    let crucible::model::ResolvedFaultTarget::NetworkPath { direction, .. } =
                        &transition.target
                    else {
                        return Err(SchedulerError::BoundaryViolation {
                            message: String::from(
                                "route transition action did not target a network path",
                            ),
                        });
                    };
                    let (source, destination) = self
                        .topology
                        .network_path_endpoints(&transition.old_route, *direction)
                        .map_err(|error| SchedulerError::BoundaryViolation {
                            message: format!("resolve route-transition path endpoints: {error}"),
                        })?;
                    let _dropped = staged_scheduler.drop_network_inflight_for_route(
                        &crucible::NodeId {
                            name: source.as_str().to_owned(),
                        },
                        &crucible::NodeId {
                            name: destination.as_str().to_owned(),
                        },
                    )?;
                }
            }
            if !removed_route_opportunities.is_empty() {
                for queue in staged_effect_state.queues.values_mut() {
                    queue.reservations.retain(|reservation| {
                        !removed_route_opportunities.contains(&reservation.opportunity)
                    });
                }
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
            let backpressure_wakeup = route::apply_network_backpressure_transitions(
                &mut staged_effect_state,
                &mut staged_pending,
                &evaluation.actions,
                &self.topology,
                coordinate.virtual_nanos,
            )?;
            staged_scheduler.set_signal_fault_wakeup(earliest_wakeup(
                evaluation.next_wakeup_nanos,
                earliest_wakeup(boundary_application.next_wakeup_nanos, backpressure_wakeup),
            ))?;
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
        self.effect_state = staged_effect_state;
        for record in records {
            self.transition_ledger.insert(record.action, record);
        }
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
    append_evidence_count(
        material,
        output.fault_continuation.protocol_expansion_path().len(),
    )?;
    for ordinal in output.fault_continuation.protocol_expansion_path() {
        material.extend_from_slice(&ordinal.to_be_bytes());
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
    for (key, current) in &state.state_machines {
        append_network_effect_state_key(material, key)?;
        append_evidence_bytes(material, current.as_str().as_bytes())?;
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
    state.boundary.append_evidence(material)
}

const fn network_queue_discipline_tag(discipline: crucible::model::NetworkQueueDiscipline) -> u8 {
    match discipline {
        crucible::model::NetworkQueueDiscipline::Fifo => 1,
        crucible::model::NetworkQueueDiscipline::StrictPriority => 2,
        crucible::model::NetworkQueueDiscipline::WeightedRoundRobin => 3,
        crucible::model::NetworkQueueDiscipline::DeficitRoundRobin => 4,
        crucible::model::NetworkQueueDiscipline::Red => 5,
    }
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
                mtu_bytes: 1500,
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
            down_plan(segment.clone()),
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
        let transition = interceptor
            .transition_ledger
            .values()
            .next()
            .unwrap_or_else(|| panic!("transition ledger should contain the applied action"));
        assert_eq!(transition.in_flight.frame_count, 1);
        assert_eq!(transition.queued.len(), 1);
        assert_eq!(transition.old_state, NetworkAvailabilityState::Up);
        assert_eq!(pending_outputs.len(), 1);
        assert_eq!(pending_outputs[0].source, destination);
        assert_eq!(pending_outputs[0].destination, source);
        assert!(pending_outputs[0].route.is_some());
        let checkpoint = interceptor
            .checkpoint(&scheduler, &pending_outputs, &mut nodes)
            .unwrap_or_else(|error| panic!("network checkpoint should encode: {error}"));
        let restored_scenario = SchedulerLivenessScenario::from_runnable_world(
            "production-availability-drop",
            Shift::default(),
            16,
            SimInstant { nanos: 128 },
            0,
            &world,
        );
        let mut restored_scheduler = SingleScheduler::from_world(
            restored_scenario,
            &world,
            &MemoryDagStore::new(),
            WorldIoLayoutPolicy::default(),
        )
        .unwrap_or_else(|error| panic!("restored scheduler should build: {error}"));
        let malformed = interceptor
            .runtime
            .checkpoint_with_network_state(
                &mut nodes,
                ProductionNetworkStateCheckpoint::new(
                    ContentHash::from_bytes(b"unauthenticated-network-state"),
                    scheduler.network_checkpoint(),
                    pending_outputs.clone(),
                    b"{}".to_vec(),
                ),
            )
            .unwrap_or_else(|error| {
                panic!("malformed fixture should authenticate outside: {error}")
            });
        let scheduler_before_rejection = restored_scheduler
            .network_continuation_digest()
            .unwrap_or_else(|error| panic!("scheduler should digest: {error}"));
        let mut rejected_pending = Vec::new();
        let error = ProductionFaultNetworkInterceptor::restore(
            down_plan(segment.clone()),
            Some(Arc::new(NoArtifacts)),
            ContentHash::from_bytes(b"production-availability-drop"),
            malformed,
            &mut nodes,
            world.fault_topology().clone(),
            world.links().to_vec(),
            &mut restored_scheduler,
            &mut rejected_pending,
        )
        .err()
        .unwrap_or_else(|| panic!("malformed adapter checkpoint should fail closed"));
        assert!(error.to_string().contains("network adapter checkpoint"));
        assert_eq!(
            restored_scheduler
                .network_continuation_digest()
                .unwrap_or_else(|digest_error| panic!("scheduler should digest: {digest_error}")),
            scheduler_before_rejection
        );
        assert!(rejected_pending.is_empty());
        let mut restored_pending = Vec::new();
        let restored_interceptor = ProductionFaultNetworkInterceptor::restore(
            down_plan(segment),
            Some(Arc::new(NoArtifacts)),
            ContentHash::from_bytes(b"production-availability-drop"),
            checkpoint.clone(),
            &mut nodes,
            world.fault_topology().clone(),
            world.links().to_vec(),
            &mut restored_scheduler,
            &mut restored_pending,
        )
        .unwrap_or_else(|error| panic!("network continuation should restore: {error}"));
        let restored_checkpoint = restored_interceptor
            .checkpoint(&restored_scheduler, &restored_pending, &mut nodes)
            .unwrap_or_else(|error| panic!("restored checkpoint should encode: {error}"));
        assert_eq!(restored_checkpoint.id(), checkpoint.id());
        assert_eq!(restored_pending, pending_outputs);
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
