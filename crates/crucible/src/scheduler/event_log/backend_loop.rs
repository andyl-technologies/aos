//! Live-backend adapter for the authoritative scheduler quantum loop.

use super::*;
use crate::BackendEffect;

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

    /// Returns the exact pre-routing network-output interceptor.
    #[must_use]
    pub const fn network_output_interceptor(&self) -> &I {
        &self.network_output_interceptor
    }

    /// Returns mutable access to the exact pre-routing interceptor.
    #[must_use]
    pub fn network_output_interceptor_mut(&mut self) -> &mut I {
        &mut self.network_output_interceptor
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

    /// Returns mutable access to the loop, backend, and interceptor together.
    ///
    /// This is the production transaction seam for operations whose checkpoint
    /// or boundary evaluation must bind scheduler state, backend state, and the
    /// signal-network continuation without aliasing any component.
    #[must_use]
    pub fn parts_with_network_interceptor_mut(&mut self) -> (&mut L, &mut B, &mut I) {
        (
            &mut self.loop_impl,
            &mut self.backend,
            &mut self.network_output_interceptor,
        )
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

    /// Consumes the adapter and returns its parts.
    #[must_use]
    pub fn into_parts(self) -> (L, B) {
        (self.loop_impl, self.backend)
    }
}

impl<L, B, I> QuantumLoop for BackendQuantumLoop<L, B, I>
where
    L: QuantumLoop,
    B: SimulationBackend,
    I: BackendNetworkOutputInterceptor<L, B>,
{
    fn drive_quantum(&mut self, request: QuantumRequest) -> Result<QuantumOutcome, SchedulerError> {
        let mut outcome = self.loop_impl.drive_quantum(request)?;
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
        for event in &outcome.resolved_events {
            let ScheduledEventPayload::BackendInput(input) = &event.payload else {
                continue;
            };
            let backend_time = self
                .loop_impl
                .backend_effect_time(&input.node, event.key.virtual_time())?;
            self.backend.apply_to_node(
                &input.node,
                &BackendEffect::DeliverInput(input.clone()),
                backend_time,
            )?;
        }
        self.pending_network_outputs
            .extend(self.backend.drain_network_outputs()?);
        let mut timed_network_outputs = std::mem::take(&mut self.pending_network_outputs)
            .into_iter()
            .map(|output| {
                self.loop_impl
                    .backend_network_output_time(&output.source, output.emit_icount)
                    .map(|at| (at, output))
            })
            .collect::<Result<Vec<_>, _>>()?;
        timed_network_outputs.sort_by(|(left_at, left), (right_at, right)| {
            (
                left_at,
                &left.source,
                left.sequence,
                &left.destination,
                &left.route,
                &left.payload,
            )
                .cmp(&(
                    right_at,
                    &right.source,
                    right.sequence,
                    &right.destination,
                    &right.route,
                    &right.payload,
                ))
        });
        let committed = timed_network_outputs
            .partition_point(|(at, _output)| at.ticks <= outcome.frontier.ticks);
        self.pending_network_outputs = timed_network_outputs
            .drain(committed..)
            .map(|(_at, output)| output)
            .collect();
        let mut network_outputs = timed_network_outputs
            .into_iter()
            .map(|(_at, output)| output)
            .collect::<Vec<_>>();
        if !network_outputs.is_empty() {
            let appends = self.network_output_interceptor.intercept_network_outputs(
                &mut self.loop_impl,
                &mut self.backend,
                outcome.frontier,
                &mut self.pending_network_outputs,
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
            let (recorded, configuration, append) = self
                .loop_impl
                .append_backend_network_outputs(network_outputs)?;
            outcome.decisions.extend(recorded);
            outcome.configuration = configuration;
            outcome.event_log_entries.extend(append.entries);
            outcome.event_log_segment_bytes = append.segment_bytes;
            outcome.event_log_segment_text = append.segment_text;
            outcome.event_log_segment_hash = append.segment_hash;
            outcome.event_log_offset = append.offset;
        }
        let causal_decisions = self.backend.drain_causal_decisions()?;
        if !causal_decisions.is_empty() {
            let (recorded, configuration, append) = self
                .loop_impl
                .append_backend_causal_decisions(causal_decisions)?;
            outcome.decisions.extend(recorded);
            outcome.configuration = configuration;
            outcome.event_log_entries.extend(append.entries);
            outcome.event_log_segment_bytes = append.segment_bytes;
            outcome.event_log_segment_text = append.segment_text;
            outcome.event_log_segment_hash = append.segment_hash;
            outcome.event_log_offset = append.offset;
        }
        self.pending_observations
            .extend(self.backend.drain_observable_events()?);
        self.pending_observations.sort_by_key(ObservableEvent::at);
        let committed = self
            .pending_observations
            .partition_point(|event| event.at().ticks <= outcome.frontier.ticks);
        let observations = self
            .pending_observations
            .drain(..committed)
            .collect::<Vec<_>>();
        if !observations.is_empty() {
            let append = self
                .loop_impl
                .append_backend_observations_at_boundary(observations, outcome.frontier)?;
            outcome.event_log_entries.extend(append.entries);
            outcome.event_log_segment_bytes = append.segment_bytes;
            outcome.event_log_segment_text = append.segment_text;
            outcome.event_log_segment_hash = append.segment_hash;
            outcome.event_log_offset = append.offset;
        }
        Ok(outcome)
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

    fn open_gdbstub(
        &mut self,
        node: NodeId,
        listen: GdbListen,
    ) -> Result<GdbAttachInfo, SchedulerError> {
        self.backend.open_gdbstub(node, listen).map_err(Into::into)
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

    fn append_backend_causal_decisions(
        &mut self,
        decisions: Vec<Decision>,
    ) -> Result<(Vec<Decision>, Configuration, SchedulerEventLogAppend), SchedulerError> {
        self.loop_impl.append_backend_causal_decisions(decisions)
    }

    fn append_backend_network_outputs(
        &mut self,
        outputs: Vec<BackendNetworkOutput>,
    ) -> Result<(Vec<Decision>, Configuration, SchedulerEventLogAppend), SchedulerError> {
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
                .map(|(_recorded, _configuration, append)| append.entries)
                .map_err(|error| BackendError::Rejected {
                    message: error.to_string(),
                })
        });
        let final_decisions = self.backend.drain_causal_decisions();
        let final_decision_append = match final_decisions {
            Ok(decisions) if decisions.is_empty() => Ok(Vec::new()),
            Ok(decisions) => self
                .loop_impl
                .append_backend_causal_decisions(decisions)
                .map(|(_recorded, _configuration, append)| append.entries),
            Err(error) => Err(SchedulerError::from(error)),
        };
        let final_observations = self.backend.drain_observable_events();
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
        entries.extend(final_decision_append?);
        entries.extend(final_append.map_err(SchedulerError::from)?);
        entries.extend(loop_result?);
        backend_result?;
        Ok(entries)
    }
}
