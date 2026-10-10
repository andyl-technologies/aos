//! Linear resource ownership for one exact hot-fork child generation.

use super::*;
use crucible_qemu::{
    LinuxQemuHotForkChildProcessAuthority, QemuHotForkChildProcessBasis,
    QemuHotForkChildProcessOwner, QemuNodeChannelError,
};

/// Linear target-resource share for one exact child generation.
///
/// This value can check and charge the shared attempt contract, but it cannot
/// release aggregate enforcement. Its [`QemuAttemptResourceGuard::finish`]
/// implementation records only that this exact child completed target cleanup;
/// the owning [`QemuHotForkWorldResourceOwner`] performs final release.
#[must_use = "finish the hot-fork node target only after exact child reap"]
pub(crate) struct QemuHotForkWorldNodeTarget<G>
where
    G: QemuAttemptResourceGuard,
{
    #[cfg(test)]
    pub(crate) component_ram_facts: bool,
    pub(super) state: Arc<Mutex<QemuHotForkWorldResourceState<G>>>,
    pub(super) identity: ProductionVmNodeGeneration,
    pub(super) resources: AttemptResourceLimits,
    pub(super) cancellation: ExecutionCancellation,
    pub(super) released: bool,
    pub(super) process_contract: Option<QemuChildProcessContract>,
    pub(super) host_ram: Option<(
        crucible_qemu::ram_control::RamControlRegistration,
        crucible_linux_resource::host_supervision::HostOperationSupervisor,
        crucible_qemu::QemuRamLaunchCustody,
    )>,
}

impl<G> fmt::Debug for QemuHotForkWorldNodeTarget<G>
where
    G: QemuAttemptResourceGuard,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QemuHotForkWorldNodeTarget")
            .field("identity", &self.identity)
            .field("released", &self.released)
            .finish_non_exhaustive()
    }
}

impl<G> QemuHotForkWorldNodeTarget<G>
where
    G: QemuAttemptResourceGuard,
{
    /// Returns the exact node-generation reservation represented by this share.
    #[must_use]
    pub const fn identity(&self) -> &ProductionVmNodeGeneration {
        &self.identity
    }

    pub(crate) fn install_host_ram_registration(
        &mut self,
        registration: crucible_qemu::ram_control::RamControlRegistration,
        supervisor: crucible_linux_resource::host_supervision::HostOperationSupervisor,
    ) -> Result<(), QemuVmRealizationError> {
        if self.host_ram.is_some()
            || registration.target.owner_generation != self.identity.generation()
        {
            return Err(world_resource_error(
                "hot-fork RAM ownership was reused or names another node generation",
            ));
        }
        let custody = crucible_qemu::QemuRamLaunchCustody::new(&registration);
        self.host_ram = Some((registration, supervisor, custody));
        Ok(())
    }

    pub(crate) fn host_ram_registration(
        &self,
    ) -> Option<&crucible_qemu::ram_control::RamControlRegistration> {
        self.host_ram
            .as_ref()
            .map(|(registration, _, _)| registration)
    }

    pub(crate) fn host_operation_supervisor(
        &self,
    ) -> Option<&crucible_linux_resource::host_supervision::HostOperationSupervisor> {
        self.host_ram.as_ref().map(|(_, supervisor, _)| supervisor)
    }

    pub(crate) fn host_ram_custody(&self) -> Option<&crucible_qemu::QemuRamLaunchCustody> {
        self.host_ram.as_ref().map(|(_, _, custody)| custody)
    }

    pub(crate) fn abort_without_child(mut self) -> Result<(), QemuVmRealizationError> {
        #[cfg(test)]
        if self.component_ram_facts
            && let Some((registration, _, _)) = &self.host_ram
        {
            registration
                .registrar
                .retire_unpublished_after_cleanup(registration.target, registration.resources)
                .map_err(|error| world_resource_error(error.to_string()))?;
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| world_resource_error("hot-fork world resource registry is poisoned"))?;
        if state.terminal
            || state.released.contains(&self.identity)
            || !state.issued.remove(&self.identity)
        {
            return Err(world_resource_error(
                "hot-fork world no-child rollback lost its exact reservation",
            ));
        }
        self.released = true;
        Ok(())
    }

    fn finish_node(&mut self) -> Result<(), QemuVmRealizationError> {
        if self.released {
            return Ok(());
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| world_resource_error("hot-fork world resource registry is poisoned"))?;
        if state.released.contains(&self.identity) {
            self.released = true;
            return Ok(());
        }
        if state.terminal || !state.issued.contains(&self.identity) {
            return Err(world_resource_error(
                "hot-fork node target is not active in its aggregate owner",
            ));
        }
        #[cfg(test)]
        if self.component_ram_facts
            && let Some((registration, _, _)) = &self.host_ram
        {
            // The scripted reconciliation owner calls this only after its
            // real child process is reaped. It has no native pager stage.
            registration
                .registrar
                .retire_unpublished_after_cleanup(registration.target, registration.resources)
                .map_err(|error| world_resource_error(error.to_string()))?;
        }
        state.released.insert(self.identity.clone());
        self.released = true;
        Ok(())
    }
}

impl<G> QemuAttemptOperationalBoundary for QemuHotForkWorldNodeTarget<G>
where
    G: QemuAttemptResourceGuard,
{
    fn resource_limits(&self) -> AttemptResourceLimits {
        self.resources
    }

    fn cancellation(&self) -> &ExecutionCancellation {
        &self.cancellation
    }

    fn check_operational_boundary(&mut self) -> Result<(), QemuVmRealizationError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| world_resource_error("hot-fork world resource registry is poisoned"))?;
        if self.released || state.terminal || !state.issued.contains(&self.identity) {
            return Err(world_resource_error(
                "hot-fork node target is not operational",
            ));
        }
        state.guard.check_operational_boundary()
    }

    fn charge_execution_quantum(&mut self) -> Result<(), QemuVmRealizationError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| world_resource_error("hot-fork world resource registry is poisoned"))?;
        if self.released || state.terminal || !state.issued.contains(&self.identity) {
            return Err(world_resource_error(
                "hot-fork node target is not operational",
            ));
        }
        state.guard.charge_execution_quantum()
    }
}

impl<G> QemuAttemptResourceGuard for QemuHotForkWorldNodeTarget<G>
where
    G: QemuAttemptResourceGuard,
{
    fn finish(&mut self) -> Result<(), QemuVmRealizationError> {
        self.finish_node()
    }

    fn quarantine(&mut self) {
        if !self.released {
            quarantine_world_state(&self.state);
            self.released = true;
        }
    }
}

impl<G> QemuAttemptProcessResourceGuard for QemuHotForkWorldNodeTarget<G>
where
    G: QemuAttemptProcessResourceGuard,
{
    fn native_resource_controller(
        &mut self,
    ) -> Result<Option<crucible_qemu::LinuxQemuNativeResourceController>, QemuVmRealizationError>
    {
        let mut state = self
            .state
            .lock()
            .map_err(|_| world_resource_error("hot-fork world resource registry is poisoned"))?;
        if self.released || state.terminal || !state.issued.contains(&self.identity) {
            return Err(world_resource_error(
                "native resource controller owner is not operational",
            ));
        }
        state.guard.native_resource_controller()
    }

    fn child_process_contract(&self) -> Result<&QemuChildProcessContract, QemuVmRealizationError> {
        if self.released {
            return Err(world_resource_error(
                "hot-fork node launch target is already released",
            ));
        }
        self.process_contract.as_ref().ok_or_else(|| {
            world_resource_error("hot-fork node target has no concurrent process contract")
        })
    }

    fn prepare_generation_run_directory(
        &mut self,
        requirements: QemuLaunchResourceRequirements,
    ) -> Result<QemuPreparedRunDirectory, QemuVmRealizationError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| world_resource_error("hot-fork world resource registry is poisoned"))?;
        if self.released || state.terminal || !state.issued.contains(&self.identity) {
            return Err(world_resource_error(
                "hot-fork node launch target is not operational",
            ));
        }
        state.guard.prepare_generation_run_directory(requirements)
    }

    fn retain_failed_launch_child(&mut self, child: QemuNodeChild) {
        match self.state.lock() {
            Ok(mut state) => {
                state.guard.retain_failed_launch_child(child);
                state.guard.quarantine();
                state.terminal = true;
                state.terminal_failure = Some(String::from(
                    "concurrent hot-fork node retained an unreaped launch child",
                ));
            }
            Err(poisoned) => {
                let mut state = poisoned.into_inner();
                state.guard.retain_failed_launch_child(child);
                state.guard.quarantine();
                state.terminal = true;
                state.terminal_failure = Some(String::from(
                    "concurrent hot-fork node resource registry was poisoned",
                ));
            }
        }
        self.released = true;
    }
}

impl<G> QemuHotForkChildProcessOwner for QemuHotForkWorldNodeTarget<G>
where
    G: QemuAttemptProcessResourceGuard
        + QemuHotForkChildProcessOwner<Authority = LinuxQemuHotForkChildProcessAuthority>,
{
    type Authority = LinuxQemuHotForkChildProcessAuthority;

    fn retain_hot_fork_child(
        &mut self,
        basis: QemuHotForkChildProcessBasis,
    ) -> Result<Self::Authority, QemuNodeChannelError> {
        let mut state = self.state.lock().map_err(|_| {
            QemuNodeChannelError::new(
                "retain concurrent hot-fork child",
                "hot-fork world resource registry is poisoned",
            )
        })?;
        if self.released || state.terminal || !state.issued.contains(&self.identity) {
            return Err(QemuNodeChannelError::new(
                "retain concurrent hot-fork child",
                "hot-fork node launch target is not operational",
            ));
        }
        state.guard.retain_hot_fork_child(basis)
    }
}

impl<G> Drop for QemuHotForkWorldNodeTarget<G>
where
    G: QemuAttemptResourceGuard,
{
    fn drop(&mut self) {
        if !self.released && !world_node_is_released(&self.state, &self.identity) {
            quarantine_world_state(&self.state);
        }
    }
}

fn world_node_is_released<G>(
    state: &Arc<Mutex<QemuHotForkWorldResourceState<G>>>,
    identity: &ProductionVmNodeGeneration,
) -> bool
where
    G: QemuAttemptResourceGuard,
{
    match state.lock() {
        Ok(state) => state.released.contains(identity),
        Err(_) => false,
    }
}
