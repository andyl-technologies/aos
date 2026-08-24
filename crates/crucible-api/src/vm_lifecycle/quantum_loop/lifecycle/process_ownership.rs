//! Exact process-identity ownership transfer for terminal lifecycle commits.

use super::*;

impl ProductionVmLifecycleLoop {
    pub(in crate::vm_lifecycle::quantum_loop) fn validate_terminal_process_ownership(
        &self,
        node: &NodeId,
        service_state: ProductionNodeServiceState,
    ) -> Result<(), SchedulerError> {
        if service_state == ProductionNodeServiceState::PermanentlyFailed {
            return Ok(());
        }
        if !self.run_manifest.processes.contains_key(&node.name) {
            return Err(SchedulerError::BoundaryViolation {
                message: format!(
                    "terminal replacement for `{}` lost its current process identity",
                    node.name
                ),
            });
        }
        let journal_identity = self
            .lifecycle_journal
            .nodes
            .iter()
            .find(|journal_node| journal_node.node == node.name)
            .and_then(|journal_node| journal_node.replacement_process.as_ref());
        let manifest_identity = self.run_manifest.staged_processes.get(&node.name);
        if journal_identity.is_none() || journal_identity != manifest_identity {
            return Err(SchedulerError::BoundaryViolation {
                message: format!(
                    "terminal replacement for `{}` lost its exact staged process identity",
                    node.name
                ),
            });
        }
        Ok(())
    }

    pub(in crate::vm_lifecycle::quantum_loop) fn commit_terminal_process_ownership(
        &mut self,
        node: &NodeId,
        service_state: ProductionNodeServiceState,
    ) -> Result<(), SchedulerError> {
        if service_state == ProductionNodeServiceState::PermanentlyFailed {
            self.run_manifest.processes.remove(&node.name);
            self.run_manifest.staged_processes.remove(&node.name);
            return Ok(());
        }
        let expected_identity = self
            .lifecycle_journal
            .nodes
            .iter()
            .find(|journal_node| journal_node.node == node.name)
            .and_then(|journal_node| journal_node.replacement_process.as_ref())
            .ok_or_else(|| SchedulerError::BoundaryViolation {
                message: format!(
                    "committed replacement for `{}` lost its process identity",
                    node.name
                ),
            })?;
        let identity = self
            .run_manifest
            .staged_processes
            .remove(&node.name)
            .ok_or_else(|| SchedulerError::BoundaryViolation {
                message: format!(
                    "committed replacement for `{}` lost its staged manifest owner",
                    node.name
                ),
            })?;
        if &identity != expected_identity {
            return Err(SchedulerError::BoundaryViolation {
                message: format!(
                    "committed replacement for `{}` changed its staged process identity",
                    node.name
                ),
            });
        }
        let process = self
            .run_manifest
            .processes
            .get_mut(&node.name)
            .ok_or_else(|| SchedulerError::BoundaryViolation {
                message: format!(
                    "committed replacement for `{}` lost its manifest owner",
                    node.name
                ),
            })?;
        *process = identity;
        Ok(())
    }
}
