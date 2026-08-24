//! Exact process-identity ownership transfer for terminal lifecycle commits.

use super::*;

impl ProductionVmLifecycleLoop {
    pub(in crate::vm_lifecycle::quantum_loop) fn validate_terminal_process_ownership(
        &self,
        node: &NodeId,
        service_state: ProductionNodeServiceState,
    ) -> Result<(), SchedulerError> {
        let journal_node = self
            .lifecycle_journal
            .nodes
            .iter()
            .find(|journal_node| journal_node.node == node.name)
            .ok_or_else(|| SchedulerError::BoundaryViolation {
                message: format!(
                    "terminal replacement for `{}` lost its journal process identity",
                    node.name
                ),
            })?;
        if self.run_manifest.processes.get(&node.name) != Some(&journal_node.current_process) {
            return Err(SchedulerError::BoundaryViolation {
                message: format!(
                    "terminal replacement for `{}` changed its current process identity",
                    node.name
                ),
            });
        }
        let journal_identity = journal_node.replacement_process.as_ref();
        let manifest_identity = self.run_manifest.staged_processes.get(&node.name);
        if !terminal_process_ownership_is_exact(
            service_state,
            &journal_node.transition,
            journal_identity,
            manifest_identity,
        ) {
            return Err(SchedulerError::BoundaryViolation {
                message: format!(
                    "terminal replacement for `{}` has inconsistent transition or staged process ownership",
                    node.name,
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

fn terminal_process_ownership_is_exact(
    service_state: ProductionNodeServiceState,
    transition: &str,
    journal_identity: Option<&QemuProcessIdentity>,
    manifest_identity: Option<&QemuProcessIdentity>,
) -> bool {
    match (service_state, transition) {
        (ProductionNodeServiceState::Running, "Crash")
        | (ProductionNodeServiceState::PoweredOff, "PowerOff") => {
            journal_identity.is_some() && journal_identity == manifest_identity
        }
        (ProductionNodeServiceState::PermanentlyFailed, "PermanentFailure") => {
            journal_identity.is_none() && manifest_identity.is_none()
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(process_id: u32) -> QemuProcessIdentity {
        QemuProcessIdentity {
            process_id,
            start_time_ticks: u64::from(process_id) + 1,
            executable: PathBuf::from("/aos/qemu"),
        }
    }

    #[test]
    fn terminal_process_ownership_binds_service_state_to_exact_transition() {
        let replacement = identity(2);
        for (state, transition) in [
            (ProductionNodeServiceState::Running, "Crash"),
            (ProductionNodeServiceState::PoweredOff, "PowerOff"),
        ] {
            assert!(terminal_process_ownership_is_exact(
                state,
                transition,
                Some(&replacement),
                Some(&replacement),
            ));
            assert!(!terminal_process_ownership_is_exact(
                state,
                "PermanentFailure",
                Some(&replacement),
                Some(&replacement),
            ));
        }
        assert!(terminal_process_ownership_is_exact(
            ProductionNodeServiceState::PermanentlyFailed,
            "PermanentFailure",
            None,
            None,
        ));
        assert!(!terminal_process_ownership_is_exact(
            ProductionNodeServiceState::PermanentlyFailed,
            "Crash",
            None,
            None,
        ));
    }
}
