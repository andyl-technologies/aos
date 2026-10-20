//! Projection of lifecycle and assertion state into observable events.

use super::*;

impl ProductionVmLifecycleLoop {
    pub(super) fn production_node_fault_evidence(
        &self,
        node: &NodeId,
    ) -> Result<ProductionNodeFaultEvidence, SchedulerError> {
        let generation = self.node_generations.get(node).copied().ok_or_else(|| {
            SchedulerError::BoundaryViolation {
                message: format!("production node `{}` has no generation", node.name),
            }
        })?;
        let service_state = match self.node_service_states.get(node) {
            Some(ProductionNodeServiceState::Running) => "running",
            Some(ProductionNodeServiceState::PoweredOff) => "powered_off",
            Some(ProductionNodeServiceState::PermanentlyFailed) => "permanently_failed",
            None => {
                return Err(SchedulerError::BoundaryViolation {
                    message: format!("production node `{}` has no service state", node.name),
                });
            }
        };
        let scheduler_activity = self.inner.loop_impl().vm_node_activity(node)?;
        let backend_owned = self.inner.backend().contains(node);
        let backend_identity = if backend_owned {
            Some(self.inner.backend().process_identity(node)?)
        } else {
            None
        };
        let manifest_identity = self.run_manifest.processes.get(&node.name);
        let staged_identity = self.run_manifest.staged_processes.get(&node.name);
        let process_ownership = match (backend_identity.as_ref(), manifest_identity) {
            (Some(backend), Some(manifest)) if backend == manifest && staged_identity.is_none() => {
                "exact"
            }
            (None, None) if staged_identity.is_none() => "absent",
            _ => "inconsistent",
        };
        Ok(ProductionNodeFaultEvidence {
            node: node.clone(),
            generation,
            service_state,
            scheduler_activity,
            backend_owned,
            process_ownership,
        })
    }
}

pub(super) fn initial_node_state_events(
    source: &ScenarioDefForm,
    at: VirtualTime,
) -> Vec<ObservableEvent> {
    source
        .world()
        .vm_nodes()
        .iter()
        .map(|node| ObservableEvent::node_state(at, node.id.clone(), NodeLifecycle::Started))
        .collect()
}

pub(super) fn assertion_state_event_from_outcome(
    outcome: &HostAssertionOutcome,
) -> Option<ObservableEvent> {
    let state = match outcome.kind {
        HostAssertionOutcomeKind::Satisfied => AssertionPhase::Satisfied,
        HostAssertionOutcomeKind::Violated => AssertionPhase::Violated,
        HostAssertionOutcomeKind::Passed
        | HostAssertionOutcomeKind::Warning
        | HostAssertionOutcomeKind::NeverEvaluated
        | HostAssertionOutcomeKind::NeverTriggered
        | HostAssertionOutcomeKind::NeverReachedWarn
        | HostAssertionOutcomeKind::NeverReachedFail => return None,
    };
    Some(ObservableEvent::assertion_state_changed(
        outcome.at,
        outcome.assertion.clone(),
        state,
    ))
}
