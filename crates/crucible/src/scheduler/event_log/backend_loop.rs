//! Live-backend adapter for the authoritative scheduler quantum loop.

use super::*;
use crate::BackendEffect;

/// Advances one live backend and drains it at completed scheduler boundaries.
#[derive(Clone, Debug)]
pub struct BackendQuantumLoop<L, B> {
    pub(super) loop_impl: L,
    pub(super) backend: B,
    pending_observations: Vec<ObservableEvent>,
    committed_frontier: VirtualTime,
}

impl<L, B> BackendQuantumLoop<L, B> {
    /// Builds an adapter from an authoritative quantum loop and backend.
    #[must_use]
    pub const fn new(loop_impl: L, backend: B) -> Self {
        Self {
            loop_impl,
            backend,
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

    /// Consumes the adapter and returns its parts.
    #[must_use]
    pub fn into_parts(self) -> (L, B) {
        (self.loop_impl, self.backend)
    }
}

impl<L, B> QuantumLoop for BackendQuantumLoop<L, B>
where
    L: QuantumLoop,
    B: SimulationBackend,
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
        let network_outputs = self.backend.drain_network_outputs()?;
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

    fn search_frontiers(&self) -> Result<Vec<SearchRuntimeFrontier>, SchedulerError> {
        self.loop_impl.search_frontiers()
    }

    fn pending_search_branch_choices(&self) -> usize {
        self.loop_impl.pending_search_branch_choices()
    }

    fn shutdown(&mut self) -> Result<Vec<SchedulerEventLogEntry>, SchedulerError> {
        let final_network_outputs = self.backend.drain_network_outputs();
        let final_network_append = match final_network_outputs {
            Ok(outputs) if outputs.is_empty() => Ok(Vec::new()),
            Ok(outputs) => self
                .loop_impl
                .append_backend_network_outputs(outputs)
                .map(|(_recorded, _configuration, append)| append.entries),
            Err(error) => Err(SchedulerError::from(error)),
        };
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
