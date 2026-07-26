//! Live-backend adapter for the authoritative scheduler quantum loop.

use super::*;

/// Advances one live backend and drains it at completed scheduler boundaries.
#[derive(Clone, Debug)]
pub struct BackendQuantumLoop<L, B> {
    pub(super) loop_impl: L,
    pub(super) backend: B,
}

impl<L, B> BackendQuantumLoop<L, B> {
    /// Builds an adapter from an authoritative quantum loop and backend.
    #[must_use]
    pub const fn new(loop_impl: L, backend: B) -> Self {
        Self { loop_impl, backend }
    }

    /// Returns the wrapped quantum loop.
    #[must_use]
    pub const fn loop_impl(&self) -> &L {
        &self.loop_impl
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
        if outcome.advanced_node.is_some() {
            let backend_step = self.backend.step_to(outcome.frontier)?;
            if backend_step.requested_ceiling != outcome.frontier
                || backend_step.reached != outcome.frontier
            {
                return Err(SchedulerError::BoundaryViolation {
                    message: format!(
                        "backend step reached {} for scheduler frontier {}",
                        backend_step.reached.ticks, outcome.frontier.ticks
                    ),
                });
            }
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
        let observations = self.backend.drain_observable_events()?;
        if !observations.is_empty() {
            let append = self
                .loop_impl
                .append_backend_observable_events(observations)?;
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

    fn shutdown(&mut self) -> Result<Vec<SchedulerEventLogEntry>, SchedulerError> {
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
        let final_append = match final_observations {
            Ok(events) if events.is_empty() => Ok(Vec::new()),
            Ok(events) => self
                .loop_impl
                .append_backend_observable_events(events)
                .map(|append| append.entries),
            Err(error) => Err(SchedulerError::from(error)),
        };
        let loop_result = self.loop_impl.shutdown();
        let backend_result = self.backend.shutdown().map_err(SchedulerError::from);
        let mut entries = final_decision_append?;
        entries.extend(final_append?);
        entries.extend(loop_result?);
        backend_result?;
        Ok(entries)
    }
}
