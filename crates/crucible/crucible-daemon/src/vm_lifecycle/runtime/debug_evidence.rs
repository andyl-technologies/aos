//! Live debugger replay evidence and candidate verification.

use super::*;

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
