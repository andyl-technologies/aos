//! Live-backend adapter for the authoritative scheduler quantum loop.

use super::*;
use crate::BackendEffect;

mod admission;
mod backend_shutdown;
mod cap_boundary;
mod device_group;
mod dispatch_boundary;
mod fixed_input;
mod held_boundary;
mod held_delivery;
mod held_lineage;
mod held_stop;
mod host_concurrent;
mod host_run_validation;
mod input_boundary;
mod io_inventory;
mod preselection;
mod settlement;
use crate::scheduler::device_group_selection::DeviceGroupSelectionController;
use admission::{BackendBoundaryEvidence, BackendOutcomeAdmission, complete_backend_outcome_on};
pub use cap_boundary::FailedCapNegotiation;
pub use dispatch_boundary::FailedDispatchResolution;
pub(in crate::scheduler) use held_delivery::HeldDeliveryCeiling;
pub(in crate::scheduler) use held_lineage::HeldRunLineage;
use held_stop::HeldHostStopController;
pub use held_stop::{HeldHostStopKind, HeldHostStopWitness};
use host_concurrent::HeldHostContinuation;
pub use input_boundary::FailedInputResolution;
use preselection::{BackendPendingPreselection, append_to_outcome};
pub use settlement::BackendNetworkSettlement;

fn pending_network_output_time<L: QuantumLoop>(
    loop_impl: &L,
    frozen_times: &BTreeMap<(NodeId, u64), VirtualTime>,
    output: &BackendNetworkOutput,
) -> Result<VirtualTime, SchedulerError> {
    if let Some(at) = frozen_times.get(&(output.source.clone(), output.sequence)) {
        return Ok(*at);
    }
    loop_impl.backend_network_output_time(&output.source, output.emit_icount)
}

/// Intercepts committed live-backend network outputs before link resolution.
///
/// The interceptor runs after every output has been translated to scheduler
/// time and admitted by the current frontier, but before the authoritative
/// scheduler routes or mutates any frame. Production signal adapters use this
/// seam to evaluate exact network opportunities and install their resolved
/// state on scheduler-owned links. Implementations must preserve canonical
/// output ordering; any payload or recipient mutation is itself modeled state.
pub trait BackendNetworkOutputInterceptor<L, B> {
    /// Applies exact pre-routing work to one canonically ordered output batch.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when an opportunity, adapter transaction, or
    /// modeled output mutation cannot be completed atomically.
    fn intercept_network_outputs(
        &mut self,
        loop_impl: &mut L,
        backend: &mut B,
        frontier: VirtualTime,
        pending_outputs: &mut Vec<BackendNetworkOutput>,
        outputs: &mut Vec<BackendNetworkOutput>,
    ) -> Result<Vec<SchedulerEventLogAppend>, SchedulerError>;
}

/// Inert interceptor used by backends without signal-driven network effects.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoopBackendNetworkOutputInterceptor;

impl<L, B> BackendNetworkOutputInterceptor<L, B> for NoopBackendNetworkOutputInterceptor {
    fn intercept_network_outputs(
        &mut self,
        _loop_impl: &mut L,
        _backend: &mut B,
        _frontier: VirtualTime,
        _pending_outputs: &mut Vec<BackendNetworkOutput>,
        _outputs: &mut Vec<BackendNetworkOutput>,
    ) -> Result<Vec<SchedulerEventLogAppend>, SchedulerError> {
        Ok(Vec::new())
    }
}

/// Advances one live backend and drains it at completed scheduler boundaries.
#[derive(Debug)]
pub struct BackendQuantumLoop<L, B, I = NoopBackendNetworkOutputInterceptor> {
    pub(super) loop_impl: L,
    pub(super) backend: B,
    // The first RUN/fixed-input selection binds the contract before its effects.
    dispatch_contract: Option<crate::BackendDispatchContract>,
    network_output_interceptor: I,
    pending_network_outputs: Vec<BackendNetworkOutput>,
    // Pending frames may outlive a selectable pause. Their pre-pause emission
    // times must survive the resumed VM's physical-counter rebase.
    frozen_network_output_times: BTreeMap<(NodeId, u64), VirtualTime>,
    pending_observations: Vec<ObservableEvent>,
    committed_frontier: VirtualTime,
    continuation_poisoned: bool,
    pause_before_live_network_choice: bool,
    parallel_choice_free_boot: bool,
    preselection: Option<BackendPendingPreselection>,
    held_host_continuation: Option<HeldHostContinuation>,
    failed_input_resolution: Option<FailedInputResolution>,
    pending_fixed_input: Option<fixed_input::RetainedFixedInput>,
    device_group_selection: DeviceGroupSelectionController,
    failed_cap_negotiation: Option<FailedCapNegotiation>,
    failed_dispatch_resolution: Option<FailedDispatchResolution>,
    held_stop_generation: u64,
    held_union_generation: u64,
    held_stop_controller: HeldHostStopController,
}

impl<L: Clone, B: Clone, I: Clone> Clone for BackendQuantumLoop<L, B, I> {
    fn clone(&self) -> Self {
        Self {
            loop_impl: self.loop_impl.clone(),
            backend: self.backend.clone(),
            dispatch_contract: self.dispatch_contract,
            network_output_interceptor: self.network_output_interceptor.clone(),
            pending_network_outputs: self.pending_network_outputs.clone(),
            frozen_network_output_times: self.frozen_network_output_times.clone(),
            pending_observations: self.pending_observations.clone(),
            committed_frontier: self.committed_frontier,
            continuation_poisoned: self.continuation_poisoned,
            pause_before_live_network_choice: self.pause_before_live_network_choice,
            parallel_choice_free_boot: self.parallel_choice_free_boot,
            preselection: self.preselection.clone(),
            held_host_continuation: self.held_host_continuation.clone(),
            failed_input_resolution: self.failed_input_resolution.clone(),
            pending_fixed_input: self.pending_fixed_input.clone(),
            device_group_selection: self.device_group_selection.clone(),
            failed_cap_negotiation: self.failed_cap_negotiation.clone(),
            failed_dispatch_resolution: self.failed_dispatch_resolution.clone(),
            held_stop_generation: self.held_stop_generation,
            held_union_generation: self.held_union_generation,
            // A cloned mock world has its own controller authority. Witness
            // clones retain the original identity and cannot cross this fork.
            held_stop_controller: HeldHostStopController::new(),
        }
    }
}

impl<L, B: SimulationBackend, I> BackendQuantumLoop<L, B, I> {
    pub(super) fn selected_dispatch_contract(
        &mut self,
    ) -> Result<crate::BackendDispatchContract, SchedulerError> {
        let current = self.backend.dispatch_contract();
        match self.dispatch_contract {
            Some(selected) if selected != current => Err(SchedulerError::BoundaryViolation {
                message: String::from("backend dispatch contract changed after selection"),
            }),
            Some(selected) => Ok(selected),
            None => {
                self.dispatch_contract = Some(current);
                Ok(current)
            }
        }
    }
}

fn observation_kind(payload: &ObservableEventPayload) -> &'static str {
    match payload {
        ObservableEventPayload::NetworkDelivered { .. } => "network-delivered",
        ObservableEventPayload::ConsoleOutput { .. } => "console-output",
        ObservableEventPayload::CoverageBlock { .. } => "coverage-block",
        ObservableEventPayload::CoverageMarker { .. } => "coverage-marker",
        ObservableEventPayload::AssertionProximity { .. } => "assertion-proximity",
        ObservableEventPayload::MemorySample { .. } => "memory-sample",
        ObservableEventPayload::IoCompletion { .. } => "io-completion",
        ObservableEventPayload::NodeState { .. } => "node-state",
        ObservableEventPayload::AssertionStateChanged { .. } => "assertion-state-changed",
        ObservableEventPayload::AssertionEvaluated { .. } => "assertion-evaluated",
        ObservableEventPayload::GuestMarker { .. } => "guest-marker",
        ObservableEventPayload::GuestMeasurement { .. } => "guest-measurement",
        ObservableEventPayload::GuestSemanticMarker { .. } => "guest-semantic-marker",
        ObservableEventPayload::GuestAssertionMarker { .. } => "guest-assertion-marker",
    }
}

fn normalize_backend_observations(
    loop_impl: &impl QuantumLoop,
    events: Vec<ObservableEvent>,
    frontier: VirtualTime,
) -> Result<Vec<ObservableEvent>, SchedulerError> {
    let poll_boundary = loop_impl.backend_observation_poll_boundary(frontier);
    events
        .into_iter()
        .map(|event| {
            let Some(node) = event.backend_node() else {
                return Ok(event.normalize_backend_poll_boundary(poll_boundary));
            };
            let at = loop_impl.backend_observation_time(node, event.at())?;
            Ok(event
                .with_scheduler_time(at)
                .normalize_backend_poll_boundary(poll_boundary))
        })
        .collect()
}

impl<L, B> BackendQuantumLoop<L, B, NoopBackendNetworkOutputInterceptor> {
    /// Builds an adapter from an authoritative quantum loop and backend.
    #[must_use]
    pub fn new(loop_impl: L, backend: B) -> Self {
        Self {
            loop_impl,
            backend,
            dispatch_contract: None,
            network_output_interceptor: NoopBackendNetworkOutputInterceptor,
            pending_network_outputs: Vec::new(),
            frozen_network_output_times: BTreeMap::new(),
            pending_observations: Vec::new(),
            committed_frontier: VirtualTime { ticks: 0 },
            continuation_poisoned: false,
            pause_before_live_network_choice: false,
            parallel_choice_free_boot: false,
            preselection: None,
            held_host_continuation: None,
            failed_input_resolution: None,
            pending_fixed_input: None,
            device_group_selection: DeviceGroupSelectionController::default(),
            failed_cap_negotiation: None,
            failed_dispatch_resolution: None,
            held_stop_generation: 0,
            held_union_generation: 0,
            held_stop_controller: HeldHostStopController::new(),
        }
    }
}

impl<L, B, I> BackendQuantumLoop<L, B, I> {
    fn retained_network_outputs(&self) -> impl Iterator<Item = &BackendNetworkOutput> {
        self.pending_network_outputs
            .iter()
            .chain(self.preselection.iter().flat_map(|pending| {
                pending
                    .pending_network_outputs
                    .iter()
                    .chain(&pending.remaining_outputs)
                    .chain(&pending.remaining_unintercepted_outputs)
            }))
    }

    fn prune_frozen_network_output_times(&mut self) {
        if self.frozen_network_output_times.is_empty() {
            return;
        }
        let active = self
            .retained_network_outputs()
            .map(|output| (output.source.clone(), output.sequence))
            .collect::<BTreeSet<_>>();
        self.frozen_network_output_times
            .retain(|key, _| active.contains(key));
    }

    /// Builds an adapter with an exact pre-routing network-output interceptor.
    #[must_use]
    pub fn with_network_output_interceptor(
        loop_impl: L,
        backend: B,
        network_output_interceptor: I,
    ) -> Self {
        Self {
            loop_impl,
            backend,
            dispatch_contract: None,
            network_output_interceptor,
            pending_network_outputs: Vec::new(),
            frozen_network_output_times: BTreeMap::new(),
            pending_observations: Vec::new(),
            committed_frontier: VirtualTime { ticks: 0 },
            continuation_poisoned: false,
            pause_before_live_network_choice: false,
            parallel_choice_free_boot: false,
            preselection: None,
            held_host_continuation: None,
            failed_input_resolution: None,
            pending_fixed_input: None,
            device_group_selection: DeviceGroupSelectionController::default(),
            failed_cap_negotiation: None,
            failed_dispatch_resolution: None,
            held_stop_generation: 0,
            held_union_generation: 0,
            held_stop_controller: HeldHostStopController::new(),
        }
    }

    /// Builds an adapter from an authenticated concrete continuation.
    ///
    /// This constructor installs scheduler-owned pending network outputs in the
    /// same operation as the restored interceptor and committed frontier. It is
    /// intentionally distinct from the fresh-run constructor so a restore can
    /// never briefly publish an empty pending-output queue.
    #[must_use]
    pub fn from_restored_network_state(
        loop_impl: L,
        backend: B,
        network_output_interceptor: I,
        pending_network_outputs: Vec<BackendNetworkOutput>,
        committed_frontier: VirtualTime,
    ) -> Self {
        Self {
            loop_impl,
            backend,
            dispatch_contract: None,
            network_output_interceptor,
            pending_network_outputs,
            frozen_network_output_times: BTreeMap::new(),
            pending_observations: Vec::new(),
            committed_frontier,
            continuation_poisoned: false,
            pause_before_live_network_choice: false,
            parallel_choice_free_boot: false,
            preselection: None,
            held_host_continuation: None,
            failed_input_resolution: None,
            pending_fixed_input: None,
            device_group_selection: DeviceGroupSelectionController::default(),
            failed_cap_negotiation: None,
            failed_dispatch_resolution: None,
            held_stop_generation: 0,
            held_union_generation: 0,
            held_stop_controller: HeldHostStopController::new(),
        }
    }

    /// Returns retained publication progress for an input-boundary RUN.
    ///
    /// No readmission or retry is authorized by this diagnostic record. Only
    /// explicit successful backend teardown retires a failed resolution. A
    /// healthy held boundary may retain progress before final settlement.
    #[must_use]
    pub const fn failed_input_resolution(&self) -> Option<&FailedInputResolution> {
        self.failed_input_resolution.as_ref()
    }

    /// Returns retained ownership when physical-cap readmission failed.
    #[must_use]
    pub const fn failed_cap_negotiation(&self) -> Option<&FailedCapNegotiation> {
        self.failed_cap_negotiation.as_ref()
    }

    /// Returns cleanup-only ownership of a failed internal dispatch settlement.
    #[must_use]
    pub const fn failed_dispatch_resolution(&self) -> Option<&FailedDispatchResolution> {
        self.failed_dispatch_resolution.as_ref()
    }

    /// Returns the wrapped quantum loop.
    #[must_use]
    pub const fn loop_impl(&self) -> &L {
        &self.loop_impl
    }

    /// Returns mutable access to the wrapped quantum loop.
    #[must_use]
    pub fn loop_impl_mut(&mut self) -> &mut L {
        &mut self.loop_impl
    }

    /// Returns the wrapped backend.
    #[must_use]
    pub const fn backend(&self) -> &B {
        &self.backend
    }

    /// Returns mutable access to the wrapped backend.
    #[must_use]
    pub fn backend_mut(&mut self) -> &mut B {
        &mut self.backend
    }

    fn poison_continuation(&mut self, error: SchedulerError) -> SchedulerError {
        self.continuation_poisoned = true;
        error
    }

    /// Returns the exact pre-routing network-output interceptor.
    #[must_use]
    pub const fn network_output_interceptor(&self) -> &I {
        &self.network_output_interceptor
    }

    /// Returns the disjoint live backend and host network interceptor together.
    #[must_use]
    pub fn backend_and_network_output_interceptor_mut(&mut self) -> (&mut B, &mut I) {
        (&mut self.backend, &mut self.network_output_interceptor)
    }

    /// Returns the number of emitted frames awaiting global-frontier commitment.
    #[must_use]
    pub fn pending_network_output_count(&self) -> usize {
        self.pending_network_outputs.len()
    }

    /// Returns mutable access to the authoritative loop and live backend together.
    ///
    /// This is the transaction seam for boundary operations that must update
    /// scheduler-owned state and a live backend atomically. Returning both
    /// disjoint fields avoids temporarily moving either continuation out of the
    /// adapter.
    #[must_use]
    pub fn parts_mut(&mut self) -> (&mut L, &mut B) {
        (&mut self.loop_impl, &mut self.backend)
    }

    /// Returns every continuation component participating in network transitions.
    ///
    /// The pending-output queue is included because an availability transition
    /// can apply a queued-operation policy before those future-timestamp frames
    /// reach the ordinary pre-routing interceptor.
    #[must_use]
    pub fn network_transaction_parts_mut(
        &mut self,
    ) -> (&mut L, &mut B, &mut I, &mut Vec<BackendNetworkOutput>) {
        (
            &mut self.loop_impl,
            &mut self.backend,
            &mut self.network_output_interceptor,
            &mut self.pending_network_outputs,
        )
    }

    /// Returns the scheduler frontier through which backend output is committed.
    #[must_use]
    pub const fn committed_frontier(&self) -> VirtualTime {
        self.committed_frontier
    }

    /// Consumes the adapter and returns its parts.
    #[must_use]
    pub fn into_parts(self) -> (L, B) {
        (self.loop_impl, self.backend)
    }
}

impl<L, B, I> BackendQuantumLoop<L, B, I>
where
    L: QuantumLoop,
    B: SimulationBackend,
    I: BackendNetworkOutputInterceptor<L, B>,
{
    #[cfg(test)]
    pub(crate) fn complete_test_observation_boundary(
        &mut self,
        request: QuantumRequest,
    ) -> Result<QuantumOutcome, SchedulerError> {
        let outcome = self.loop_impl.drive_quantum(request)?;
        assert!(
            outcome.advanced_node.is_none(),
            "observation fixture cannot execute a physical RUN"
        );
        self.committed_frontier = outcome.frontier;
        let evidence = BackendBoundaryEvidence {
            staged_inputs: BTreeSet::new(),
            rng_evidence: self.backend.drain_rng_evidence()?,
            network_outputs: self.backend.drain_network_outputs()?,
            observations: self.backend.drain_observable_events()?,
        };
        complete_backend_outcome_on(
            BackendOutcomeAdmission {
                loop_impl: &mut self.loop_impl,
                backend: &mut self.backend,
                network_output_interceptor: &mut self.network_output_interceptor,
                pending_network_outputs: &mut self.pending_network_outputs,
                frozen_network_output_times: &mut self.frozen_network_output_times,
                pending_observations: &mut self.pending_observations,
                preselection: &mut self.preselection,
                pause_before_live_network_choice: self.pause_before_live_network_choice,
                network_release_at: outcome.frontier,
            },
            outcome,
            evidence,
        )
    }

    /// Reports whether failed physical or logical settlement forbids continuation.
    ///
    /// A poisoned continuation retains ownership for whole-world teardown and
    /// cannot admit a new RUN, offered stop, queued publication, or checkpoint.
    #[must_use]
    pub const fn continuation_is_poisoned(&self) -> bool {
        self.continuation_poisoned
    }

    /// Captures existing pending frames' logical emission times before a VM rebase.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] if an unfrozen frame's backend counter cannot
    /// be projected onto the current scheduler timeline.
    pub fn pending_network_output_times_for_node(
        &self,
        node: &NodeId,
    ) -> Result<Vec<(u64, VirtualTime)>, SchedulerError> {
        self.retained_network_outputs()
            .filter(|output| &output.source == node)
            .map(|output| {
                pending_network_output_time(
                    &self.loop_impl,
                    &self.frozen_network_output_times,
                    output,
                )
                .map(|at| (output.sequence, at))
            })
            .collect()
    }

    /// Retains a pre-rebase emission time for each already pending VM frame.
    pub fn retain_pending_network_output_times(
        &mut self,
        node: &NodeId,
        times: Vec<(u64, VirtualTime)>,
    ) {
        for (sequence, at) in times {
            self.frozen_network_output_times
                .insert((node.clone(), sequence), at);
        }
    }

    /// Settles scheduler-owned network frames due at the exact current frontier.
    ///
    /// This does not step or drain the backend. It exists for boundary mutations
    /// that make an already-pending frame due at the current coordinate.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when timestamp conversion, signal adaptation,
    /// link resolution, or event-log commitment fails.
    pub fn settle_pending_network_outputs_at_current_frontier(
        &mut self,
    ) -> Result<BackendNetworkSettlement, SchedulerError> {
        if self.continuation_poisoned {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from("backend continuation is poisoned"),
            });
        }
        if self.preselection.is_some() {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from(
                    "queued network release cannot cross an unresolved preselection",
                ),
            });
        }
        if self.held_host_continuation.is_some() {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from(
                    "held physical RUNs must settle before queued network release",
                ),
            });
        }
        let pending_before = self.pending_network_outputs.clone();
        match self.settle_pending_network_outputs_at_current_frontier_inner() {
            Ok(settlement) => {
                self.prune_frozen_network_output_times();
                Ok(settlement)
            }
            Err(error) => {
                self.pending_network_outputs = pending_before;
                self.continuation_poisoned = true;
                Err(error)
            }
        }
    }

    fn settle_pending_network_outputs_at_current_frontier_inner(
        &mut self,
    ) -> Result<BackendNetworkSettlement, SchedulerError> {
        let frontier = self.committed_frontier;
        let mut timed_network_outputs = std::mem::take(&mut self.pending_network_outputs)
            .into_iter()
            .map(|output| {
                pending_network_output_time(
                    &self.loop_impl,
                    &self.frozen_network_output_times,
                    &output,
                )
                .map(|at| {
                    let resume = VirtualTime {
                        ticks: output.fault_continuation.cursor().not_before_ticks(),
                    };
                    (at.max(resume), output)
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        timed_network_outputs.sort_by(|(left_at, left), (right_at, right)| {
            (
                left_at,
                left.fault_continuation
                    .cursor()
                    .queue_priority()
                    .unwrap_or(crate::model::NetworkBundlePriority::Normal.rank()),
                &left.source,
                left.sequence,
                &left.destination,
                &left.route,
                &left.fault_continuation,
                &left.payload,
            )
                .cmp(&(
                    right_at,
                    right
                        .fault_continuation
                        .cursor()
                        .queue_priority()
                        .unwrap_or(crate::model::NetworkBundlePriority::Normal.rank()),
                    &right.source,
                    right.sequence,
                    &right.destination,
                    &right.route,
                    &right.fault_continuation,
                    &right.payload,
                ))
        });
        let committed =
            timed_network_outputs.partition_point(|(at, _output)| at.ticks <= frontier.ticks);
        self.pending_network_outputs = timed_network_outputs
            .drain(committed..)
            .map(|(_at, output)| output)
            .collect();
        let network_outputs = timed_network_outputs
            .into_iter()
            .map(|(_at, output)| output)
            .collect::<Vec<_>>();
        let batches = if self.pause_before_live_network_choice {
            network_outputs
                .into_iter()
                .map(|output| self.loop_impl.backend_network_routes(output))
                .collect::<Result<Vec<_>, _>>()?
                .into_iter()
                .flatten()
                .map(|output| vec![output])
                .collect()
        } else {
            vec![network_outputs]
        };
        let mut batches = batches.into_iter();
        let mut appends = Vec::new();
        let mut decisions = Vec::new();
        let mut discoveries = Vec::new();
        let mut configuration = None;
        while let Some(mut network_outputs) = batches.next() {
            if network_outputs.is_empty() {
                continue;
            }
            appends.extend(self.network_output_interceptor.intercept_network_outputs(
                &mut self.loop_impl,
                &mut self.backend,
                frontier,
                &mut self.pending_network_outputs,
                &mut network_outputs,
            )?);
            if network_outputs.is_empty() {
                continue;
            }
            let routes_are_exact = if self.pause_before_live_network_choice {
                network_outputs.iter().try_fold(true, |exact, output| {
                    self.loop_impl
                        .backend_network_route_count(output)
                        .map(|count| exact && count == 1)
                })?
            } else {
                false
            };
            if self.pause_before_live_network_choice && !routes_are_exact {
                return Err(SchedulerError::BoundaryViolation {
                    message: String::from(
                        "queued live network choice pause requires an exact directed World route",
                    ),
                });
            }
            let admission = if self.pause_before_live_network_choice {
                self.loop_impl.append_backend_network_outputs_until_choice(
                    network_outputs,
                    &self.frozen_network_output_times,
                )?
            } else {
                let (decisions, discoveries, configuration, append) =
                    self.loop_impl.append_backend_network_outputs(
                        network_outputs,
                        &self.frozen_network_output_times,
                    )?;
                BackendNetworkAdmission::Settled {
                    decisions,
                    discoveries,
                    configuration,
                    append,
                }
            };
            let (recorded, discovered, advanced, append, pending) = match admission {
                BackendNetworkAdmission::Settled {
                    decisions,
                    discoveries,
                    configuration,
                    append,
                } => (decisions, discoveries, configuration, append, None),
                BackendNetworkAdmission::Preselection {
                    decisions,
                    discoveries,
                    configuration,
                    append,
                    reservation,
                    remaining,
                } => (
                    decisions,
                    discoveries,
                    configuration,
                    append,
                    Some((*reservation, remaining)),
                ),
            };
            decisions.extend(recorded);
            discoveries.extend(discovered);
            configuration = Some(advanced.clone());
            appends.push(append);
            if let Some((choice, remaining_outputs)) = pending {
                let mut outcome = QuantumOutcome {
                    configuration: advanced,
                    frontier,
                    advanced_node: None,
                    resolved_events: Vec::new(),
                    decisions: decisions.clone(),
                    discovered_choices: discoveries,
                    event_log_entries: Vec::new(),
                    event_log_segment_bytes: Vec::new(),
                    event_log_segment_text: String::new(),
                    event_log_segment_hash: None,
                    event_log_offset: EventLogOffset::default(),
                    scheduler_quiescence: None,
                };
                for append in &appends {
                    append_to_outcome(&mut outcome, append.clone());
                }
                self.preselection = Some(BackendPendingPreselection {
                    choice,
                    remaining_outputs,
                    remaining_unintercepted_outputs: batches.flatten().collect(),
                    pending_network_outputs: std::mem::take(&mut self.pending_network_outputs),
                    pending_observations: std::mem::take(&mut self.pending_observations),
                    rng_evidence: Vec::new(),
                    observations: Vec::new(),
                    outcome: outcome.clone(),
                    handed_off: false,
                    selected: None,
                    selected_decision_count: 0,
                    selected_event_count: 0,
                });
                return Ok(BackendNetworkSettlement {
                    decisions,
                    configuration,
                    appends,
                    reservation: Some(outcome),
                });
            }
        }
        Ok(BackendNetworkSettlement {
            decisions,
            configuration,
            appends,
            reservation: None,
        })
    }
}

impl<B, I> QuantumLoop for BackendQuantumLoop<SingleScheduler, B, I>
where
    B: ConcurrentSimulationBackend,
    I: BackendNetworkOutputInterceptor<SingleScheduler, B> + Clone,
{
    fn drive_quantum(&mut self, request: QuantumRequest) -> Result<QuantumOutcome, SchedulerError> {
        let batch = self.drive_concurrent_quantum(request, 1)?;
        let mut outcomes = batch.outcomes.into_iter();
        let mut merged = outcomes
            .next()
            .ok_or_else(|| SchedulerError::BoundaryViolation {
                message: String::from("causal host round returned no scheduler completion"),
            })?;
        for outcome in outcomes {
            merged.configuration = outcome.configuration;
            merged.frontier = outcome.frontier;
            merged.advanced_node = outcome.advanced_node;
            merged.resolved_events.extend(outcome.resolved_events);
            merged.decisions.extend(outcome.decisions);
            merged.discovered_choices.extend(outcome.discovered_choices);
            merged.event_log_entries.extend(outcome.event_log_entries);
            merged.event_log_segment_bytes = outcome.event_log_segment_bytes;
            merged.event_log_segment_text = outcome.event_log_segment_text;
            merged.event_log_segment_hash = outcome.event_log_segment_hash;
            merged.event_log_offset = outcome.event_log_offset;
            merged.scheduler_quiescence = outcome.scheduler_quiescence;
        }
        Ok(merged)
    }

    fn sample_fingerprint(&mut self, node: NodeId) -> Result<FingerprintSample, SchedulerError> {
        let sample = self.backend.fingerprint(node.clone())?;
        let at = self.loop_impl.backend_observation_time(&node, sample.at)?;

        // The backend reports its node-local counter; public fingerprint time
        // uses the same scheduler epoch as other observations from that node.
        Ok(FingerprintSample { at, ..sample })
    }

    fn apply_control_at_boundary(
        &mut self,
        control: Vec<ControlOperation>,
    ) -> Result<Vec<SchedulerEventLogEntry>, SchedulerError> {
        if self.device_group_selection.is_retained() {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from("control cannot cross an original Device Group selection"),
            });
        }
        self.loop_impl.apply_control_at_boundary(control)
    }

    fn append_noncanonical_debug_event_log_entries(
        &mut self,
        entries: Vec<SchedulerEventLogEntry>,
    ) -> Result<Vec<SchedulerEventLogEntry>, SchedulerError> {
        self.loop_impl
            .append_noncanonical_debug_event_log_entries(entries)
    }

    fn open_gdbstub(
        &mut self,
        node: NodeId,
        listen: GdbListen,
    ) -> Result<GdbAttachInfo, SchedulerError> {
        self.backend.open_gdbstub(node, listen).map_err(Into::into)
    }

    fn activate_debug_guest(&mut self, node: NodeId) -> Result<(), SchedulerError> {
        self.backend.activate_debug_guest(&node).map_err(Into::into)
    }

    fn send_guest_introspection(
        &mut self,
        node: NodeId,
        record: crucible_protocol::guest_introspection::GuestIntrospectionRecord,
    ) -> Result<(), SchedulerError> {
        self.backend
            .send_guest_introspection(&node, record)
            .map_err(Into::into)
    }

    fn receive_guest_introspection(
        &mut self,
        node: NodeId,
    ) -> Result<
        Option<crucible_protocol::guest_introspection::GuestIntrospectionRecord>,
        SchedulerError,
    > {
        self.backend
            .receive_guest_introspection(&node)
            .map_err(Into::into)
    }

    fn append_backend_observable_events(
        &mut self,
        events: Vec<ObservableEvent>,
    ) -> Result<SchedulerEventLogAppend, SchedulerError> {
        self.loop_impl.append_backend_observable_events(events)
    }

    fn append_backend_evaluation_boundary(
        &mut self,
        at: VirtualTime,
    ) -> Result<SchedulerEventLogAppend, SchedulerError> {
        self.loop_impl.append_backend_evaluation_boundary(at)
    }

    fn append_backend_observations_at_boundary(
        &mut self,
        events: Vec<ObservableEvent>,
        at: VirtualTime,
    ) -> Result<SchedulerEventLogAppend, SchedulerError> {
        self.loop_impl
            .append_backend_observations_at_boundary(events, at)
    }

    fn append_backend_rng_evidence(
        &mut self,
        evidence: Vec<BackendRngEvidence>,
    ) -> Result<
        (
            Vec<Decision>,
            Vec<crucible_campaign::ChoiceDiscovery>,
            Configuration,
            SchedulerEventLogAppend,
        ),
        SchedulerError,
    > {
        self.loop_impl.append_backend_rng_evidence(evidence)
    }

    fn append_backend_network_outputs(
        &mut self,
        outputs: Vec<BackendNetworkOutput>,
        emission_times: &BTreeMap<(NodeId, u64), VirtualTime>,
    ) -> Result<
        (
            Vec<Decision>,
            Vec<crucible_campaign::ChoiceDiscovery>,
            Configuration,
            SchedulerEventLogAppend,
        ),
        SchedulerError,
    > {
        let mut retained = emission_times.clone();
        retained.extend(self.frozen_network_output_times.clone());
        self.loop_impl
            .append_backend_network_outputs(outputs, &retained)
    }

    fn append_backend_network_outputs_after_selection(
        &mut self,
        outputs: Vec<BackendNetworkOutput>,
        parent: &Configuration,
        selection: &SelectionDecision,
        emission_times: &BTreeMap<(NodeId, u64), VirtualTime>,
    ) -> Result<
        (
            Vec<Decision>,
            Vec<crucible_campaign::ChoiceDiscovery>,
            Configuration,
            SchedulerEventLogAppend,
        ),
        SchedulerError,
    > {
        let mut retained = emission_times.clone();
        retained.extend(self.frozen_network_output_times.clone());
        self.loop_impl
            .append_backend_network_outputs_after_selection(outputs, parent, selection, &retained)
    }

    fn backend_network_output_time(
        &self,
        node: &NodeId,
        at: Icount,
    ) -> Result<VirtualTime, SchedulerError> {
        self.loop_impl.backend_network_output_time(node, at)
    }

    fn search_frontiers(&self) -> Result<Vec<SearchRuntimeFrontier>, SchedulerError> {
        QuantumLoop::search_frontiers(&self.loop_impl)
    }

    fn pending_search_branch_choices(&self) -> usize {
        self.loop_impl.pending_search_branch_choices()
    }

    fn shutdown(&mut self) -> Result<Vec<SchedulerEventLogEntry>, SchedulerError> {
        self.shutdown_backend_owner()
    }
}
