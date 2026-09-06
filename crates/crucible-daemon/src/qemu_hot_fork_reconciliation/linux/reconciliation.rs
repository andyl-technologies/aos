//! Ordered source observation, private-resource release, and target cleanup.

use super::*;

impl<G> QemuHotForkReconciliationBackend for LinuxQemuHotForkReconciliationBackend<G>
where
    G: crate::QemuAttemptResourceGuard,
{
    type Error = LinuxQemuHotForkReconciliationError;

    fn child_basis(&self) -> QemuHotForkReconciliationChildBasis {
        QemuHotForkReconciliationChildBasis::new(
            self.basis.request().child_process_generation(),
            self.basis.child_process_id(),
        )
    }

    fn admit_child_channel(&mut self) -> Result<(), Self::Error> {
        let endpoint = self
            .pending_child_qmp
            .take()
            .ok_or(LinuxQemuHotForkReconciliationError::BasisMismatch)?;
        let continuation = self
            .host_continuation
            .take()
            .ok_or(LinuxQemuHotForkReconciliationError::BasisMismatch)?;
        match continuation.into_scheduler_node_continuation(endpoint) {
            Ok(scheduler_node) => {
                self.scheduler_node = Some(scheduler_node);
                Ok(())
            }
            Err(error) => {
                let (continuation, endpoint, source) = error.into_parts();
                self.host_continuation = Some(continuation);
                self.pending_child_qmp = endpoint;
                Err(LinuxQemuHotForkReconciliationError::Source(source))
            }
        }
    }

    fn terminate_child(&mut self) -> Result<(), Self::Error> {
        self.process_owner.process.kill().map_err(Into::into)
    }

    fn drain_child_diagnostics(&mut self) -> Result<(), Self::Error> {
        self.diagnostics_consumer
            .drain_available()
            .map(|_drain| ())
            .map_err(Into::into)
    }

    fn observe_child(&mut self) -> Result<QemuHotForkChildObservation, Self::Error> {
        let state = self.process_owner.observe_child()?;
        qmp_child_observation(state)
    }

    fn release_next_child_resource(&mut self) -> Result<bool, Self::Error> {
        loop {
            match self.source_release {
                LinuxSourceReleasePhase::CloseChildChannel => {
                    self.pending_child_qmp = None;
                    self.scheduler_node = None;
                    self.installed_node = None;
                    self.installed_node_id = None;
                    self.host_continuation = None;
                    self.source_release = LinuxSourceReleasePhase::PluginEndpoints;
                }
                LinuxSourceReleasePhase::PluginEndpoints => {
                    self.with_source_mut(|source| source.release_hot_fork_plugin_endpoints())?;
                    self.source_release = LinuxSourceReleasePhase::ChildQmp;
                    return Ok(false);
                }
                LinuxSourceReleasePhase::ChildQmp => {
                    self.with_source_mut(|source| source.release_hot_fork_child_qmp())?;
                    self.source_release = LinuxSourceReleasePhase::Diagnostics;
                    return Ok(false);
                }
                LinuxSourceReleasePhase::Diagnostics => {
                    let process_owner = Arc::clone(&self.process_owner);
                    let mut source = process_owner.source.lock().map_err(|_source| {
                        LinuxQemuHotForkReconciliationError::SourceOwnerPoisoned
                    })?;
                    let source = source
                        .as_mut()
                        .ok_or(LinuxQemuHotForkReconciliationError::BasisMismatch)?;
                    self.diagnostics =
                        Some(source.release_hot_fork_child_diagnostics_with_consumer(
                            &mut self.diagnostics_consumer,
                        )?);
                    self.source_release = LinuxSourceReleasePhase::PrivateRing;
                    return Ok(false);
                }
                LinuxSourceReleasePhase::PrivateRing => {
                    self.with_source_mut(|source| {
                        source.release_hot_fork_private_ring_mapping().map(drop)
                    })?;
                    self.source_release = LinuxSourceReleasePhase::Complete;
                    return Ok(true);
                }
                LinuxSourceReleasePhase::Complete => return Ok(true),
            }
        }
    }

    fn release_target(&mut self) -> Result<(), Self::Error> {
        // The child's pinned run-directory descriptors go first so the target
        // guard's storage cleanup never races an authority this owner holds.
        self.run_directory = None;
        self.target.finish().map_err(Into::into)
    }

    fn release_source_status(
        &mut self,
        terminal: QemuHotForkChildObservation,
    ) -> Result<(), Self::Error> {
        let released = self.with_source_mut(|source| {
            source.release_hot_fork_child_process(terminal.generation())
        })?;
        let observed = qmp_child_observation(released)?;
        if observed != terminal || released.retained() {
            return Err(LinuxQemuHotForkReconciliationError::BasisMismatch);
        }
        Ok(())
    }

    fn release_process_contract(&mut self) -> Result<(), Self::Error> {
        let state = self.with_source_mut(QemuNode::release_hot_fork_child_process_contract)?;
        if state.staged()
            || state.consumed()
            || state.generation() != self.basis.request().child_process_contract_generation()
        {
            return Err(LinuxQemuHotForkReconciliationError::BasisMismatch);
        }
        // The consumed child-file plan is released with the contract so the
        // source can stage a fresh plan for its next child.
        let files = self.with_source_mut(QemuNode::release_hot_fork_child_files)?;
        if files.staged()
            || files.consumed()
            || files.generation() != self.basis.request().child_files_generation()
        {
            return Err(LinuxQemuHotForkReconciliationError::BasisMismatch);
        }
        Ok(())
    }

    fn quarantine(&mut self) {
        let _ = self.process_owner.process.kill();
        self.target.quarantine();
    }
}

fn qmp_child_observation(
    state: QmpHotForkChildProcessState,
) -> Result<QemuHotForkChildObservation, LinuxQemuHotForkReconciliationError> {
    let disposition = match state.phase() {
        QmpHotForkChildProcessPhase::Running => QemuHotForkChildDisposition::Running,
        QmpHotForkChildProcessPhase::Exited => QemuHotForkChildDisposition::Exited(state.status()),
        QmpHotForkChildProcessPhase::Signaled if state.status() != 0 => {
            QemuHotForkChildDisposition::Signaled(state.status())
        }
        QmpHotForkChildProcessPhase::Signaled => {
            return Err(LinuxQemuHotForkReconciliationError::BasisMismatch);
        }
    };
    QemuHotForkChildObservation::new(state.generation(), state.child_process_id(), disposition)
        .map_err(|_source| LinuxQemuHotForkReconciliationError::BasisMismatch)
}
