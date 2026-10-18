//! Whole-world teardown and final causal evidence settlement.
//!
//! Failed or unresolved owners remain cleanup-only until actual backend
//! teardown succeeds; ordinary shutdown publishes only committed evidence.

use super::*;

impl<L, B, I> BackendQuantumLoop<L, B, I>
where
    L: QuantumLoop,
    B: SimulationBackend,
    I: BackendNetworkOutputInterceptor<L, B>,
{
    pub(crate) fn shutdown_backend_owner(
        &mut self,
    ) -> Result<Vec<SchedulerEventLogEntry>, SchedulerError> {
        if self.held_host_continuation.is_some()
            || self.pending_fixed_input.is_some()
            || self.device_group_selection.is_retained()
            || self.continuation_poisoned
        {
            // Explicit whole-world teardown discards private physical evidence;
            // it never settles the source or admits a held peer receipt. Retain
            // ownership on failure so shutdown can be retried without any RUN.
            self.continuation_poisoned = true;
            self.backend.shutdown().map_err(SchedulerError::from)?;
            self.held_host_continuation = None;
            self.failed_input_resolution = None;
            self.pending_fixed_input = None;
            self.device_group_selection = Default::default();
            self.failed_cap_negotiation = None;
            self.failed_dispatch_resolution = None;
            self.preselection = None;
            self.pending_network_outputs.clear();
            self.frozen_network_output_times.clear();
            self.pending_observations.clear();
            return self.loop_impl.shutdown();
        }
        if self.preselection.is_some() {
            return self.shutdown_preselection();
        }
        let final_network_append = self.backend.drain_network_outputs().and_then(|outputs| {
            self.pending_network_outputs.extend(outputs);
            let first_uncommitted = self
                .pending_network_outputs
                .iter()
                .map(|output| {
                    pending_network_output_time(
                        &self.loop_impl,
                        &self.frozen_network_output_times,
                        output,
                    )
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
                        "{} live-backend network outputs remain uncommitted at shutdown; first future frame {} from `{}` has tick {} beyond committed frontier {}",
                        self.pending_network_outputs.len(),
                        output.sequence,
                        output.source.name,
                        at.ticks,
                        self.committed_frontier.ticks,
                    ),
                });
            }
            if self.pending_network_outputs.is_empty() {
                return Ok(Vec::new());
            }
            let outputs = std::mem::take(&mut self.pending_network_outputs);
            self.loop_impl
                .append_backend_network_outputs(
                    outputs,
                    &self.frozen_network_output_times,
                )
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
            normalize_backend_observations(&self.loop_impl, events, self.committed_frontier)
                .map_err(|error| BackendError::Rejected {
                    message: error.to_string(),
                })
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
