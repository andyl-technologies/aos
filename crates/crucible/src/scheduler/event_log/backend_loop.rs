//! Live-backend adapter for the authoritative scheduler quantum loop.

use super::*;
use crate::BackendEffect;

mod admission;
mod settlement;
use admission::{BackendBoundaryEvidence, BackendOutcomeAdmission, complete_backend_outcome_on};
mod preselection;
use preselection::{BackendPendingPreselection, append_to_outcome};
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
    pause_before_live_network_choice: bool,
    parallel_choice_free_boot: bool,
    preselection: Option<BackendPendingPreselection>,
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
            pause_before_live_network_choice: false,
            parallel_choice_free_boot: false,
            preselection: None,
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
            pause_before_live_network_choice: false,
            parallel_choice_free_boot: false,
            preselection: None,
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
            pause_before_live_network_choice: false,
            parallel_choice_free_boot: false,
            preselection: None,
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
                self.loop_impl
                    .append_backend_network_outputs_until_choice(network_outputs)?
            } else {
                let (decisions, discoveries, configuration, append) = self
                    .loop_impl
                    .append_backend_network_outputs(network_outputs)?;
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
        if self.preselection.is_some() {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from(
                    "live-network preselection must be settled or handed off before another RUN",
                ),
            });
        }
        if max_host_workers == 0 {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from("concurrent backend max_host_workers must be positive"),
            });
        }
        let prepared = if self.pause_before_live_network_choice && !self.parallel_choice_free_boot {
            self.loop_impl
                .borrow()
                .prepare_concurrent_quantum_limited(request, 1)?
        } else {
            self.loop_impl
                .borrow()
                .prepare_concurrent_quantum(request)?
        };
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
        let mut staged_preselection = None;
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
                BackendOutcomeAdmission {
                    loop_impl: &mut staged_scheduler,
                    backend: &mut self.backend,
                    network_output_interceptor: &mut staged_interceptor,
                    pending_network_outputs: &mut staged_pending_network_outputs,
                    pending_observations: &mut staged_pending_observations,
                    preselection: &mut staged_preselection,
                    pause_before_live_network_choice: self.pause_before_live_network_choice,
                },
                outcome,
                boundary,
            );
            match completed {
                Ok(outcome) => {
                    if self.parallel_choice_free_boot
                        && (staged_preselection.is_some()
                            || !outcome.discovered_choices.is_empty()
                            || outcome.decisions.iter().any(|decision| {
                                matches!(decision, Decision::Selection(_) | Decision::Override(_))
                            }))
                    {
                        return Err(self.poison_continuation(SchedulerError::BoundaryViolation {
                            message: String::from(
                                "choice-free parallel boot reached a selectable before the serial boundary",
                            ),
                        }));
                    }
                    published.push(outcome);
                }
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
        self.preselection = staged_preselection;
        self.committed_frontier = staged_frontier;
        Ok(SchedulerConcurrentQuantumOutcome {
            run_set,
            outcomes: published,
        })
    }
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
        if self.preselection.is_some() {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from(
                    "live-network preselection must be settled or handed off before another RUN",
                ),
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
        let completed = complete_backend_outcome_on(
            BackendOutcomeAdmission {
                loop_impl: &mut self.loop_impl,
                backend: &mut self.backend,
                network_output_interceptor: &mut self.network_output_interceptor,
                pending_network_outputs: &mut self.pending_network_outputs,
                pending_observations: &mut self.pending_observations,
                preselection: &mut self.preselection,
                pause_before_live_network_choice: self.pause_before_live_network_choice,
            },
            outcome,
            evidence,
        );
        completed.map_err(|error| self.poison_continuation(error))
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

    fn append_backend_network_outputs_after_selection(
        &mut self,
        outputs: Vec<BackendNetworkOutput>,
        parent: &Configuration,
        selection: &SelectionDecision,
    ) -> Result<
        (
            Vec<Decision>,
            Vec<crucible_campaign::ChoiceDiscovery>,
            Configuration,
            SchedulerEventLogAppend,
        ),
        SchedulerError,
    > {
        self.loop_impl
            .append_backend_network_outputs_after_selection(outputs, parent, selection)
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
        if self.preselection.is_some() {
            return self.shutdown_preselection();
        }
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
            if let Some(first) = self.pending_observations.first() {
                let source = first
                    .backend_node()
                    .map(|node| node.name.as_str())
                    .unwrap_or("scheduler");
                Err(BackendError::Rejected {
                    message: format!(
                        "{} live-backend observations remain uncommitted at shutdown; first timestamp is {} (kind {}, source `{source}`, committed frontier {})",
                        self.pending_observations.len(),
                        first.at().ticks,
                        observation_kind(first.payload()),
                        self.committed_frontier.ticks,
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
