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
    pub(super) retirement: WorldMemberRetirement,
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
            .field("retirement", &self.retirement)
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
        guest_ram_bytes: u64,
    ) -> Result<(), QemuVmRealizationError>
    where
        G: QemuAttemptProcessResourceGuard,
    {
        if self.host_ram.is_some()
            || registration.target.owner_generation != self.identity.generation()
        {
            return Err(world_resource_error(
                "hot-fork RAM ownership was reused or names another node generation",
            ));
        }
        let contract = self.process_contract.as_ref().ok_or_else(|| {
            world_resource_error("hot-fork RAM target has no installed process contract")
        })?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| world_resource_error("hot-fork world resource registry is poisoned"))?;
        if self.retirement != WorldMemberRetirement::Active
            || state.retirement != WorldResourceRetirement::Active
            || !state.issued.contains(&self.identity)
        {
            return Err(world_resource_error(
                "hot-fork RAM target is not operational",
            ));
        }

        let custody = crucible_qemu::QemuRamLaunchCustody::new(&registration);
        state.guard.bind_fork_target_ram_custody(
            contract,
            &registration,
            &supervisor,
            guest_ram_bytes,
            &custody,
        )?;
        drop(state);

        self.host_ram = Some((registration, supervisor, custody));
        Ok(())
    }

    /// Prepares files in the explicit component backend's temporary filesystem.
    ///
    /// The complete Source remains retained by the aggregate owner. This test
    /// operation delegates only the scripted guard's filesystem effects; it
    /// cannot lend the Source quota or construct native target authority.
    ///
    /// # Errors
    /// Refuses a released or foreign member, poisoned state or filesystem error.
    #[cfg(test)]
    pub(crate) fn prepare_component_generation_run_directory(
        &mut self,
        requirements: QemuLaunchResourceRequirements,
    ) -> Result<QemuPreparedRunDirectory, QemuVmRealizationError>
    where
        G: QemuAttemptProcessResourceGuard,
    {
        let mut state = self
            .state
            .lock()
            .map_err(|_| world_resource_error("hot-fork world resource registry is poisoned"))?;
        if self.retirement != WorldMemberRetirement::Active
            || state.retirement != WorldResourceRetirement::Active
            || !state.issued.contains(&self.identity)
        {
            return Err(world_resource_error(
                "component hot-fork node launch target is not operational",
            ));
        }
        state.guard.prepare_generation_run_directory(requirements)
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
        self.abort_without_child_retained()
    }

    /// Returns only this exact unpublished member, retaining its owner on error.
    ///
    /// The preborn Target row keeps this same value through every refusal.
    /// Calling this again after actual local return performs no second ledger
    /// mutation. Native Target return remains a separate genuine loan receipt.
    pub(crate) fn abort_without_child_retained(&mut self) -> Result<(), QemuVmRealizationError> {
        if self.retirement == WorldMemberRetirement::Returned {
            return Ok(());
        }
        if self.retirement == WorldMemberRetirement::Quarantined {
            return Err(QemuVmRealizationError::CleanupRetained {
                operation: "abort quarantined hot-fork World member",
            });
        }
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
        if state.retirement != WorldResourceRetirement::Active
            || state.released.contains(&self.identity)
            || !state.issued.remove(&self.identity)
        {
            return Err(world_resource_error(
                "hot-fork world no-child rollback lost its exact reservation",
            ));
        }
        self.retirement = WorldMemberRetirement::Returned;
        Ok(())
    }

    pub(crate) fn finish_member(&mut self) -> Result<(), QemuWorldMemberCleanupStatus> {
        match self.retirement {
            WorldMemberRetirement::Active => {}
            WorldMemberRetirement::Returned => return Ok(()),
            WorldMemberRetirement::Quarantined => {
                return Err(QemuWorldMemberCleanupStatus::Retained {
                    operation: "finish hot-fork World member",
                });
            }
        }
        let mut state = self.state.lock().map_err(|_| {
            QemuWorldMemberCleanupStatus::registry("hot-fork world resource registry is poisoned")
        })?;
        if state.released.contains(&self.identity) {
            self.retirement = WorldMemberRetirement::Returned;
            return Ok(());
        }
        if state.retirement != WorldResourceRetirement::Active
            || !state.issued.contains(&self.identity)
        {
            return Err(QemuWorldMemberCleanupStatus::registry(
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
                .map_err(|error| QemuWorldMemberCleanupStatus::registry(error.to_string()))?;
        }
        state.released.insert(self.identity.clone());
        self.retirement = WorldMemberRetirement::Returned;
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
        if self.retirement != WorldMemberRetirement::Active
            || state.retirement != WorldResourceRetirement::Active
            || !state.issued.contains(&self.identity)
        {
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
        if self.retirement != WorldMemberRetirement::Active
            || state.retirement != WorldResourceRetirement::Active
            || !state.issued.contains(&self.identity)
        {
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
    fn finish(&mut self) -> Result<(), crate::QemuAttemptResourceGuardCleanupFailure> {
        self.finish_member().map_err(|status| {
            let failure = crate::QemuAttemptResourceGuardCleanupFailure::member_status(status);
            if self.retirement == WorldMemberRetirement::Quarantined {
                failure.after_quarantine()
            } else {
                failure
            }
        })
    }

    fn quarantine(&mut self) {
        if self.retirement == WorldMemberRetirement::Active {
            quarantine_world_state(&self.state);
            self.retirement = WorldMemberRetirement::Quarantined;
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
        if self.retirement != WorldMemberRetirement::Active
            || state.retirement != WorldResourceRetirement::Active
            || !state.issued.contains(&self.identity)
        {
            return Err(world_resource_error(
                "native resource controller owner is not operational",
            ));
        }
        state.guard.native_resource_controller()
    }

    fn child_process_contract(&self) -> Result<&QemuChildProcessContract, QemuVmRealizationError> {
        if self.retirement != WorldMemberRetirement::Active {
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
        if self.retirement != WorldMemberRetirement::Active
            || state.retirement != WorldResourceRetirement::Active
            || !state.issued.contains(&self.identity)
        {
            return Err(world_resource_error(
                "hot-fork node launch target is not operational",
            ));
        }
        let contract = self.process_contract.as_ref().ok_or_else(|| {
            world_resource_error("hot-fork node target lost its installed process contract")
        })?;
        state.prepare_generation_run_directory(contract, requirements)
    }

    fn retain_failed_launch_child(&mut self, child: QemuNodeChild) {
        match self.state.lock() {
            Ok(mut state) => {
                state.guard.retain_failed_launch_child(child);
                state.guard.quarantine();
                state.retirement = WorldResourceRetirement::Retained;
                state.terminal_failure.get_or_insert_with(|| {
                    String::from("concurrent hot-fork node retained an unreaped launch child")
                });
            }
            Err(poisoned) => {
                let mut state = poisoned.into_inner();
                state.guard.retain_failed_launch_child(child);
                state.guard.quarantine();
                state.retirement = WorldResourceRetirement::Retained;
                state.terminal_failure.get_or_insert_with(|| {
                    String::from("concurrent hot-fork node resource registry was poisoned")
                });
            }
        }
        self.retirement = WorldMemberRetirement::Quarantined;
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
        if self.retirement != WorldMemberRetirement::Active
            || state.retirement != WorldResourceRetirement::Active
            || !state.issued.contains(&self.identity)
        {
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
        if self.retirement == WorldMemberRetirement::Active
            && !world_node_is_released(&self.state, &self.identity)
        {
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
