//! Live-backend adapter for the authoritative scheduler quantum loop.

use super::*;
use crate::BackendEffect;

mod settlement;
pub use settlement::BackendNetworkSettlement;

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
#[derive(Clone, Debug)]
pub struct BackendQuantumLoop<L, B, I = NoopBackendNetworkOutputInterceptor> {
    pub(super) loop_impl: L,
    pub(super) backend: B,
    network_output_interceptor: I,
    pending_network_outputs: Vec<BackendNetworkOutput>,
    pending_observations: Vec<ObservableEvent>,
    committed_frontier: VirtualTime,
    continuation_poisoned: bool,
}

struct BackendBoundaryEvidence {
    rng_evidence: Vec<BackendRngEvidence>,
    network_outputs: Vec<BackendNetworkOutput>,
    observations: Vec<ObservableEvent>,
}

impl<L, B> BackendQuantumLoop<L, B, NoopBackendNetworkOutputInterceptor> {
    /// Builds an adapter from an authoritative quantum loop and backend.
    #[must_use]
    pub const fn new(loop_impl: L, backend: B) -> Self {
        Self {
            loop_impl,
            backend,
            network_output_interceptor: NoopBackendNetworkOutputInterceptor,
            pending_network_outputs: Vec::new(),
            pending_observations: Vec::new(),
            committed_frontier: VirtualTime { ticks: 0 },
            continuation_poisoned: false,
        }
    }
}

impl<L, B, I> BackendQuantumLoop<L, B, I> {
    /// Builds an adapter with an exact pre-routing network-output interceptor.
    #[must_use]
    pub const fn with_network_output_interceptor(
        loop_impl: L,
        backend: B,
        network_output_interceptor: I,
    ) -> Self {
        Self {
            loop_impl,
            backend,
            network_output_interceptor,
            pending_network_outputs: Vec::new(),
            pending_observations: Vec::new(),
            committed_frontier: VirtualTime { ticks: 0 },
            continuation_poisoned: false,
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
            network_output_interceptor,
            pending_network_outputs,
            pending_observations: Vec::new(),
            committed_frontier,
            continuation_poisoned: false,
        }
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
        let pending_before = self.pending_network_outputs.clone();
        match self.settle_pending_network_outputs_at_current_frontier_inner() {
            Ok(settlement) => Ok(settlement),
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
                self.loop_impl
                    .backend_network_output_time(&output.source, output.emit_icount)
                    .map(|at| {
                        let resume = VirtualTime {
                            ticks: output.fault_continuation.cursor().not_before_nanos(),
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
        let mut network_outputs = timed_network_outputs
            .into_iter()
            .map(|(_at, output)| output)
            .collect::<Vec<_>>();
        let mut appends = Vec::new();
        if !network_outputs.is_empty() {
            appends.extend(self.network_output_interceptor.intercept_network_outputs(
                &mut self.loop_impl,
                &mut self.backend,
                frontier,
                &mut self.pending_network_outputs,
                &mut network_outputs,
            )?);
        }
        let (decisions, configuration) = if network_outputs.is_empty() {
            (Vec::new(), None)
        } else {
            let (decisions, _discoveries, configuration, append) = self
                .loop_impl
                .append_backend_network_outputs(network_outputs)?;
            appends.push(append);
            (decisions, Some(configuration))
        };
        Ok(BackendNetworkSettlement {
            decisions,
            configuration,
            appends,
        })
    }
}

impl<L, B, I> BackendQuantumLoop<L, B, I>
where
    L: QuantumLoop,
    B: SimulationBackend,
    I: BackendNetworkOutputInterceptor<L, B>,
{
    /// Executes one scheduler-prepared RUN set on bounded host workers.
    ///
    /// The scheduler continuation remains speculative until every backend has
    /// reached its prepublished ceiling. Successful outcomes are then applied
    /// in the scheduler's canonical completion order, independent of worker
    /// completion timing.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when planning, host dispatch, backend
    /// validation, or canonical boundary publication fails.
    fn drive_host_concurrent_quantum(
        &mut self,
        request: QuantumRequest,
        max_host_workers: usize,
    ) -> Result<SchedulerConcurrentQuantumOutcome, SchedulerError>
    where
        L: std::borrow::Borrow<SingleScheduler> + std::borrow::BorrowMut<SingleScheduler>,
        B: ConcurrentSimulationBackend,
        I: BackendNetworkOutputInterceptor<SingleScheduler, B> + Clone,
    {
        if self.continuation_poisoned {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from("backend continuation is poisoned"),
            });
        }
        if max_host_workers == 0 {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from("concurrent backend max_host_workers must be positive"),
            });
        }
        let prepared = self
            .loop_impl
            .borrow()
            .prepare_concurrent_quantum(request)?;
        let run_set = prepared.run_set().clone();
        let mut runs = Vec::with_capacity(prepared.run_set().candidates.len());
        for candidate in &prepared.run_set().candidates {
            let outcome = prepared
                .outcomes()
                .iter()
                .find(|outcome| {
                    outcome
                        .advanced_node
                        .as_ref()
                        .is_some_and(|node| node == &candidate.node)
                })
                .ok_or_else(|| SchedulerError::BoundaryViolation {
                    message: format!(
                        "prepared concurrent RUN for `{}` has no scheduler outcome",
                        candidate.node.node.name
                    ),
                })?;
            let preemptions = outcome
                .decisions
                .iter()
                .filter_map(|decision| match decision {
                    Decision::Preemption(preemption) => Some(preemption.clone()),
                    _ => None,
                })
                .collect();
            runs.push(ConcurrentBackendRun {
                node: candidate.node.node.clone(),
                ceiling: VirtualTime {
                    ticks: candidate.max_advance_icount,
                },
                preemptions,
            });
        }
        let completed = match self.backend.execute_concurrent_runs(runs, max_host_workers) {
            Ok(completed) => completed,
            Err(error) => return Err(self.poison_continuation(error.into())),
        };
        if completed.len() != prepared.run_set().candidates.len() {
            let error = SchedulerError::BoundaryViolation {
                message: String::from("host worker outcome cardinality changed"),
            };
            return Err(self.poison_continuation(error));
        }
        let mut evidence = BTreeMap::new();
        for completed in completed {
            if evidence.insert(completed.node.clone(), completed).is_some() {
                let error = SchedulerError::BoundaryViolation {
                    message: String::from("host workers repeated a scheduler RUN node"),
                };
                return Err(self.poison_continuation(error));
            }
        }
        for candidate in &prepared.run_set().candidates {
            let Some(completed) = evidence.get(&candidate.node.node) else {
                let error = SchedulerError::BoundaryViolation {
                    message: format!(
                        "host workers omitted scheduler RUN for `{}`",
                        candidate.node.node.name
                    ),
                };
                return Err(self.poison_continuation(error));
            };
            let ceiling = VirtualTime {
                ticks: candidate.max_advance_icount,
            };
            if completed.step.requested_ceiling != ceiling || completed.step.reached != ceiling {
                let error = SchedulerError::BoundaryViolation {
                    message: format!(
                        "host worker for `{}` reached {} for scheduler ceiling {}",
                        candidate.node.node.name, completed.step.reached.ticks, ceiling.ticks
                    ),
                };
                return Err(self.poison_continuation(error));
            }
        }

        let PreparedSchedulerConcurrentQuantum {
            next: mut staged_scheduler,
            outcome,
        } = prepared;
        let mut staged_interceptor = self.network_output_interceptor.clone();
        let mut staged_pending_network_outputs = self.pending_network_outputs.clone();
        let mut staged_pending_observations = self.pending_observations.clone();
        let mut staged_frontier = self.committed_frontier;
        let mut published = Vec::with_capacity(outcome.outcomes.len());
        for outcome in outcome.outcomes {
            staged_frontier = outcome.frontier;
            let boundary = if let Some(advanced) = &outcome.advanced_node {
                let Some(completed) = evidence.remove(&advanced.node) else {
                    let error = SchedulerError::BoundaryViolation {
                        message: format!(
                            "host worker evidence for `{}` was already consumed",
                            advanced.node.name
                        ),
                    };
                    return Err(self.poison_continuation(error));
                };
                BackendBoundaryEvidence {
                    rng_evidence: completed.rng_evidence,
                    network_outputs: completed.network_outputs,
                    observations: completed.observations,
                }
            } else {
                BackendBoundaryEvidence {
                    rng_evidence: Vec::new(),
                    network_outputs: Vec::new(),
                    observations: Vec::new(),
                }
            };
            let completed = complete_backend_outcome_on(
                &mut staged_scheduler,
                &mut self.backend,
                &mut staged_interceptor,
                &mut staged_pending_network_outputs,
                &mut staged_pending_observations,
                outcome,
                boundary,
            );
            match completed {
                Ok(outcome) => published.push(outcome),
                Err(error) => return Err(self.poison_continuation(error)),
            }
        }
        if !evidence.is_empty() {
            let error = SchedulerError::BoundaryViolation {
                message: String::from("host workers returned an unselected QEMU node"),
            };
            return Err(self.poison_continuation(error));
        }

        *self.loop_impl.borrow_mut() = staged_scheduler;
        self.network_output_interceptor = staged_interceptor;
        self.pending_network_outputs = staged_pending_network_outputs;
        self.pending_observations = staged_pending_observations;
        self.committed_frontier = staged_frontier;
        Ok(SchedulerConcurrentQuantumOutcome {
            run_set,
            outcomes: published,
        })
    }
}

fn complete_backend_outcome_on<L, B, I>(
    loop_impl: &mut L,
    backend: &mut B,
    network_output_interceptor: &mut I,
    pending_network_outputs: &mut Vec<BackendNetworkOutput>,
    pending_observations: &mut Vec<ObservableEvent>,
    mut outcome: QuantumOutcome,
    evidence: BackendBoundaryEvidence,
) -> Result<QuantumOutcome, SchedulerError>
where
    L: QuantumLoop,
    B: SimulationBackend,
    I: BackendNetworkOutputInterceptor<L, B>,
{
    for event in &outcome.resolved_events {
        let ScheduledEventPayload::BackendInput(input) = &event.payload else {
            continue;
        };
        let backend_time = loop_impl.backend_effect_time(&input.node, event.key.virtual_time())?;
        backend.apply_to_node(
            &input.node,
            &BackendEffect::DeliverInput(input.clone()),
            backend_time,
        )?;
    }
    let resolved_observations = outcome
        .resolved_events
        .iter()
        .map(|event| loop_impl.resolved_event_observation(event))
        .collect::<Result<Vec<_>, SchedulerError>>()?;
    pending_observations.extend(resolved_observations.into_iter().flatten());
    pending_network_outputs.extend(evidence.network_outputs);
    let mut timed_network_outputs = std::mem::take(pending_network_outputs)
        .into_iter()
        .map(|output| {
            loop_impl
                .backend_network_output_time(&output.source, output.emit_icount)
                .map(|at| {
                    let resume = VirtualTime {
                        ticks: output.fault_continuation.cursor().not_before_nanos(),
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
        timed_network_outputs.partition_point(|(at, _output)| at.ticks <= outcome.frontier.ticks);
    *pending_network_outputs = timed_network_outputs
        .drain(committed..)
        .map(|(_at, output)| output)
        .collect();
    let mut network_outputs = timed_network_outputs
        .into_iter()
        .map(|(_at, output)| output)
        .collect::<Vec<_>>();
    if !network_outputs.is_empty() {
        let appends = network_output_interceptor.intercept_network_outputs(
            loop_impl,
            backend,
            outcome.frontier,
            pending_network_outputs,
            &mut network_outputs,
        )?;
        for append in appends {
            outcome.event_log_entries.extend(append.entries);
            outcome.event_log_segment_bytes = append.segment_bytes;
            outcome.event_log_segment_text = append.segment_text;
            outcome.event_log_segment_hash = append.segment_hash;
            outcome.event_log_offset = append.offset;
        }
    }
    if !network_outputs.is_empty() {
        let (recorded, discovered_choices, configuration, append) =
            loop_impl.append_backend_network_outputs(network_outputs)?;
        outcome.decisions.extend(recorded);
        outcome.discovered_choices.extend(discovered_choices);
        outcome.configuration = configuration;
        outcome.event_log_entries.extend(append.entries);
        outcome.event_log_segment_bytes = append.segment_bytes;
        outcome.event_log_segment_text = append.segment_text;
        outcome.event_log_segment_hash = append.segment_hash;
        outcome.event_log_offset = append.offset;
    }
    let causal_decisions = evidence.rng_evidence;
    if !causal_decisions.is_empty() {
        let (recorded, discovered_choices, configuration, append) =
            loop_impl.append_backend_rng_evidence(causal_decisions)?;
        outcome.decisions.extend(recorded);
        outcome.discovered_choices.extend(discovered_choices);
        outcome.configuration = configuration;
        outcome.event_log_entries.extend(append.entries);
        outcome.event_log_segment_bytes = append.segment_bytes;
        outcome.event_log_segment_text = append.segment_text;
        outcome.event_log_segment_hash = append.segment_hash;
        outcome.event_log_offset = append.offset;
    }
    let observations = evidence
        .observations
        .into_iter()
        .map(|event| {
            let Some(node) = event.backend_node() else {
                return Ok(event);
            };
            let at = loop_impl.backend_observation_time(node, event.at())?;
            Ok(event.with_scheduler_time(at))
        })
        .collect::<Result<Vec<_>, SchedulerError>>()?;
    pending_observations.extend(observations);
    pending_observations.sort_by_key(ObservableEvent::at);
    let committed =
        pending_observations.partition_point(|event| event.at().ticks <= outcome.frontier.ticks);
    let observations = pending_observations.drain(..committed).collect::<Vec<_>>();
    if !observations.is_empty() {
        let append =
            loop_impl.append_backend_observations_at_boundary(observations, outcome.frontier)?;
        outcome.event_log_entries.extend(append.entries);
        outcome.event_log_segment_bytes = append.segment_bytes;
        outcome.event_log_segment_text = append.segment_text;
        outcome.event_log_segment_hash = append.segment_hash;
        outcome.event_log_offset = append.offset;
    }
    Ok(outcome)
}

impl<B, I> ConcurrentQuantumLoop for BackendQuantumLoop<SingleScheduler, B, I>
where
    B: ConcurrentSimulationBackend,
    I: BackendNetworkOutputInterceptor<SingleScheduler, B> + Clone,
{
    fn drive_concurrent_quantum(
        &mut self,
        request: QuantumRequest,
        max_host_workers: usize,
    ) -> Result<SchedulerConcurrentQuantumOutcome, SchedulerError> {
        self.drive_host_concurrent_quantum(request, max_host_workers)
    }
}

impl<L, B, I> QuantumLoop for BackendQuantumLoop<L, B, I>
where
    L: QuantumLoop,
    B: SimulationBackend,
    I: BackendNetworkOutputInterceptor<L, B>,
{
    fn drive_quantum(&mut self, request: QuantumRequest) -> Result<QuantumOutcome, SchedulerError> {
        if self.continuation_poisoned {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from("backend continuation is poisoned"),
            });
        }
        let outcome = self.loop_impl.drive_quantum(request)?;
        self.committed_frontier = outcome.frontier;
        if let Some(advanced_node) = outcome.advanced_node.as_ref() {
            let backend_ceiling = self.loop_impl.backend_step_ceiling(&outcome)?;
            for decision in &outcome.decisions {
                if let Decision::Preemption(preemption) = decision {
                    let at = self.backend.node_now(&preemption.node)?;
                    self.backend.apply_to_node(
                        &preemption.node,
                        &BackendEffect::Preemption(preemption.clone()),
                        at,
                    )?;
                }
            }
            let backend_step = self
                .backend
                .step_node_to(&advanced_node.node, backend_ceiling)?;
            if backend_step.requested_ceiling != backend_ceiling
                || backend_step.reached != backend_ceiling
            {
                return Err(SchedulerError::BoundaryViolation {
                    message: format!(
                        "backend step reached {} for selected-node ceiling {}",
                        backend_step.reached.ticks, backend_ceiling.ticks
                    ),
                });
            }
        }
        let evidence = BackendBoundaryEvidence {
            rng_evidence: self.backend.drain_rng_evidence()?,
            network_outputs: self.backend.drain_network_outputs()?,
            observations: self.backend.drain_observable_events()?,
        };
        complete_backend_outcome_on(
            &mut self.loop_impl,
            &mut self.backend,
            &mut self.network_output_interceptor,
            &mut self.pending_network_outputs,
            &mut self.pending_observations,
            outcome,
            evidence,
        )
    }

    fn sample_fingerprint(&mut self, node: NodeId) -> Result<FingerprintSample, SchedulerError> {
        self.backend.fingerprint(node).map_err(Into::into)
    }

    fn apply_control_at_boundary(
        &mut self,
        control: Vec<ControlOperation>,
    ) -> Result<Vec<SchedulerEventLogEntry>, SchedulerError> {
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
    ) -> Result<
        (
            Vec<Decision>,
            Vec<crucible_campaign::ChoiceDiscovery>,
            Configuration,
            SchedulerEventLogAppend,
        ),
        SchedulerError,
    > {
        self.loop_impl.append_backend_network_outputs(outputs)
    }

    fn backend_network_output_time(
        &self,
        node: &NodeId,
        at: Icount,
    ) -> Result<VirtualTime, SchedulerError> {
        self.loop_impl.backend_network_output_time(node, at)
    }

    fn search_frontiers(&self) -> Result<Vec<SearchRuntimeFrontier>, SchedulerError> {
        self.loop_impl.search_frontiers()
    }

    fn pending_search_branch_choices(&self) -> usize {
        self.loop_impl.pending_search_branch_choices()
    }

    fn shutdown(&mut self) -> Result<Vec<SchedulerEventLogEntry>, SchedulerError> {
        let final_network_append = self.backend.drain_network_outputs().and_then(|outputs| {
            self.pending_network_outputs.extend(outputs);
            let first_uncommitted = self
                .pending_network_outputs
                .iter()
                .map(|output| {
                    self.loop_impl
                        .backend_network_output_time(&output.source, output.emit_icount)
                        .map(|at| (at, output))
                        .map_err(|error| BackendError::Rejected {
                            message: error.to_string(),
                        })
                })
                .collect::<Result<Vec<_>, _>>()?
                .into_iter()
                .filter(|(at, _output)| at.ticks > self.committed_frontier.ticks)
                .min_by_key(|(at, _output)| at.ticks);
            if let Some((at, output)) = first_uncommitted {
                return Err(BackendError::Rejected {
                    message: format!(
                        "{} live-backend network outputs remain uncommitted at shutdown; frame {} from `{}` has timestamp {}",
                        self.pending_network_outputs.len(),
                        output.sequence,
                        output.source.name,
                        at.ticks
                    ),
                });
            }
            if self.pending_network_outputs.is_empty() {
                return Ok(Vec::new());
            }
            let outputs = std::mem::take(&mut self.pending_network_outputs);
            self.loop_impl
                .append_backend_network_outputs(outputs)
                .map(|(_recorded, _discoveries, _configuration, append)| append.entries)
                .map_err(|error| BackendError::Rejected {
                    message: error.to_string(),
                })
        });
        let final_decisions = match self.backend.drain_rng_evidence() {
            Ok(decisions) if decisions.is_empty() => Ok(()),
            Ok(decisions) => Err(SchedulerError::BoundaryViolation {
                message: format!(
                    "{} live-backend causal decisions remain without a quantum discovery handoff at shutdown",
                    decisions.len()
                ),
            }),
            Err(error) => Err(SchedulerError::from(error)),
        };
        let final_observations = self.backend.drain_observable_events().and_then(|events| {
            events
                .into_iter()
                .map(|event| {
                    let Some(node) = event.backend_node() else {
                        return Ok(event);
                    };
                    let at = self
                        .loop_impl
                        .backend_observation_time(node, event.at())
                        .map_err(|error| BackendError::Rejected {
                            message: error.to_string(),
                        })?;
                    Ok(event.with_scheduler_time(at))
                })
                .collect::<Result<Vec<_>, BackendError>>()
        });
        let final_append = final_observations.and_then(|events| {
            self.pending_observations.extend(events);
            self.pending_observations.sort_by_key(ObservableEvent::at);
            let committed = self
                .pending_observations
                .partition_point(|event| event.at().ticks <= self.committed_frontier.ticks);
            let observations = self
                .pending_observations
                .drain(..committed)
                .collect::<Vec<_>>();
            if !self.pending_observations.is_empty() {
                let first = self
                    .pending_observations
                    .iter()
                    .map(ObservableEvent::at)
                    .min_by_key(|at| at.ticks)
                    .unwrap_or_default();
                Err(BackendError::Rejected {
                    message: format!(
                        "{} live-backend observations remain uncommitted at shutdown; first timestamp is {}",
                        self.pending_observations.len(),
                        first.ticks
                    ),
                })
            } else if observations.is_empty() {
                Ok(Vec::new())
            } else {
                self.loop_impl
                    .append_backend_observations_at_boundary(
                        observations,
                        self.committed_frontier,
                    )
                    .map(|append| append.entries)
                    .map_err(|error| BackendError::Rejected {
                        message: error.to_string(),
                    })
            }
        });
        let loop_result = self.loop_impl.shutdown();
        let backend_result = self.backend.shutdown().map_err(SchedulerError::from);
        let mut entries = final_network_append?;
        final_decisions?;
        entries.extend(final_append.map_err(SchedulerError::from)?);
        entries.extend(loop_result?);
        backend_result?;
        Ok(entries)
    }
}
