//! Live debugger replay evidence and candidate verification.

use super::*;

impl ProductionVmDebugRuntimeEvidence {
    /// Returns the earliest recorded node time, or the graph-only fallback.
    pub(super) fn scheduler_frontier(&self, graph_fallback: VirtualTime) -> VirtualTime {
        self.node_times
            .values()
            .copied()
            .min()
            .unwrap_or(graph_fallback)
    }

    /// Matches graph identity while ignoring boundary-owned runtime evidence.
    ///
    /// A repositioned runtime carries the event-log offset and node counters
    /// from its landed boundary. Those fields must not prevent a subsequent
    /// reverse operation from resolving an earlier sample of the same reduced
    /// graph state.
    pub(super) fn matches_graph_runtime(&self, runtime: &RuntimeState) -> bool {
        self.validate_graph_runtime(runtime.configuration, runtime.id, runtime)
            .is_ok()
    }

    pub(super) fn same_sample(&self, other: &Self) -> bool {
        self.configuration == other.configuration
            && self.event_log == other.event_log
            && self.scheduler == other.scheduler
            && self.node_icounts == other.node_icounts
            && self.node_times == other.node_times
            && self.fingerprints == other.fingerprints
    }

    pub(super) fn bind_graph_runtime(&self, runtime: &RuntimeState) -> RuntimeState {
        let mut bound = runtime.clone();
        bound.configuration = self.configuration;
        bound.event_log = self.event_log;
        bound.scheduler = self.scheduler.clone();
        bound.node_icounts = self.node_icounts.clone();
        bound
    }

    pub(super) fn validate_graph_runtime(
        &self,
        configuration: ContentHash,
        reduced_state: ContentHash,
        runtime: &RuntimeState,
    ) -> Result<(), SchedulerError> {
        let graph_nodes = runtime
            .node_icounts
            .keys()
            .collect::<std::collections::BTreeSet<_>>();
        let evidence_nodes = self
            .node_icounts
            .keys()
            .collect::<std::collections::BTreeSet<_>>();
        let blob_nodes = runtime
            .node_blobs
            .keys()
            .collect::<std::collections::BTreeSet<_>>();
        let graph_nodes_valid = (graph_nodes.is_empty() && blob_nodes.is_empty())
            || (graph_nodes == evidence_nodes && blob_nodes == evidence_nodes);
        if self.configuration == configuration
            && runtime.configuration == configuration
            && runtime.id == reduced_state
            && graph_nodes_valid
        {
            return Ok(());
        }
        Err(SchedulerError::BoundaryViolation {
            message: format!(
                "graph runtime identity does not match the latest production debugger boundary: boundary_configuration_match={} runtime_configuration_match={} reduced_state_match={} node_sets_match={}",
                self.configuration == configuration,
                runtime.configuration == configuration,
                runtime.id == reduced_state,
                graph_nodes_valid,
            ),
        })
    }

    pub(super) fn matches_target(&self, request: &DebugRuntimeRepositionRequest) -> bool {
        self.configuration == request.target.id()
            && self.event_log == request.target_runtime.event_log
            && self.scheduler == request.target_runtime.scheduler
            && self.node_icounts == request.target_runtime.node_icounts
            && self.runtime.as_ref() == Some(&request.target_runtime)
    }
}

pub(super) fn debug_candidate_matches_target_runtime(
    candidate: &ProductionVmLifecycleLoop,
    request: &DebugRuntimeRepositionRequest,
) -> Result<bool, SchedulerError> {
    if candidate.inner.loop_impl().configuration() != &request.target
        || candidate.inner.loop_impl().event_log_offset() != request.target_runtime.event_log
        || candidate.inner.loop_impl().materialized_scheduler_state()
            != request.target_runtime.scheduler
    {
        return Ok(false);
    }
    let world_nodes = candidate
        .source
        .world()
        .vm_nodes()
        .iter()
        .map(|vm| vm.id.clone())
        .collect::<std::collections::BTreeSet<_>>();
    if request
        .target_runtime
        .node_icounts
        .keys()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>()
        != world_nodes
    {
        return Ok(false);
    }
    for (node, expected) in &request.target_runtime.node_icounts {
        if candidate.inner.backend().node_now(node)?.ticks != expected.retired {
            return Ok(false);
        }
    }
    Ok(true)
}

pub(super) fn verify_debug_replay_against_live_evidence(
    candidate: &mut ProductionVmLifecycleLoop,
    evidence: &ProductionVmDebugRuntimeEvidence,
) -> Result<(), SchedulerError> {
    for (node, expected) in &evidence.fingerprints {
        let actual = candidate.inner.backend_mut().fingerprint(node.clone())?;
        if actual != *expected {
            return Err(SchedulerError::BoundaryViolation {
                message: format!(
                    "whole-world debugger replay for `{}` does not match the original live execution fingerprint",
                    node.name
                ),
            });
        }
    }
    Ok(())
}

pub(super) fn verify_debug_replay_pair(
    candidate: &mut ProductionVmLifecycleLoop,
    verifier: &mut ProductionVmLifecycleLoop,
) -> Result<(), SchedulerError> {
    if candidate.inner.loop_impl().materialized_scheduler_state()
        != verifier.inner.loop_impl().materialized_scheduler_state()
    {
        return Err(SchedulerError::BoundaryViolation {
            message: String::from(
                "whole-world debugger replay candidates produced different scheduler state",
            ),
        });
    }
    for vm in candidate.source.world().vm_nodes() {
        let candidate_counter = candidate.inner.backend().node_now(&vm.id)?;
        let verifier_counter = verifier.inner.backend().node_now(&vm.id)?;
        if candidate_counter != verifier_counter {
            return Err(SchedulerError::BoundaryViolation {
                message: format!(
                    "whole-world debugger replay candidates disagree on `{}` counter",
                    vm.id.name
                ),
            });
        }
        let candidate_fingerprint = candidate.inner.backend_mut().fingerprint(vm.id.clone())?;
        let verifier_fingerprint = verifier.inner.backend_mut().fingerprint(vm.id.clone())?;
        if candidate_fingerprint != verifier_fingerprint {
            return Err(SchedulerError::BoundaryViolation {
                message: format!(
                    "whole-world debugger replay candidates disagree on `{}` execution fingerprint",
                    vm.id.name
                ),
            });
        }
    }
    Ok(())
}
