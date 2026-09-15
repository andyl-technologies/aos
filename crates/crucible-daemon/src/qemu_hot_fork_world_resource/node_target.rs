//! Linear resource ownership for one exact hot-fork child generation.

use super::*;

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
    pub(super) state: Arc<Mutex<QemuHotForkWorldResourceState<G>>>,
    pub(super) identity: ProductionVmNodeGeneration,
    pub(super) resources: AttemptResourceLimits,
    pub(super) cancellation: ExecutionCancellation,
    pub(super) released: bool,
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

    pub(crate) fn abort_without_child(mut self) -> Result<(), QemuVmRealizationError> {
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
