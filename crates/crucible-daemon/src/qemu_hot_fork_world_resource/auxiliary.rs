//! Auxiliary lifecycle resource borrowing for retained hot-fork worlds.

use super::*;

pub(super) struct QemuHotForkWorldAuxiliaryResourceHandle<G>
where
    G: QemuAttemptProcessResourceGuard,
{
    pub(super) state: Weak<Mutex<QemuHotForkWorldResourceState<G>>>,
    pub(super) resources: AttemptResourceLimits,
    pub(super) cancellation: ExecutionCancellation,
}

impl<G> Clone for QemuHotForkWorldAuxiliaryResourceHandle<G>
where
    G: QemuAttemptProcessResourceGuard,
{
    fn clone(&self) -> Self {
        Self {
            state: Weak::clone(&self.state),
            resources: self.resources,
            cancellation: self.cancellation.clone(),
        }
    }
}

struct QemuHotForkWorldAuxiliaryBrokerState<G>
where
    G: QemuAttemptProcessResourceGuard,
{
    next_token: u64,
    bound: Option<(u64, QemuHotForkWorldAuxiliaryResourceHandle<G>)>,
}

/// Per-worker rendezvous for private lifecycles sharing a retained hot World guard.
///
/// A production hot-fork lifecycle binds this broker only after primary child
/// shutdown is complete. The broker retains a weak resource handle, so it
/// cannot prolong aggregate ownership or source-publication authority.
pub(crate) struct QemuHotForkWorldAuxiliaryResourceBroker<G>
where
    G: QemuAttemptProcessResourceGuard,
{
    state: Arc<Mutex<QemuHotForkWorldAuxiliaryBrokerState<G>>>,
}

impl<G> Clone for QemuHotForkWorldAuxiliaryResourceBroker<G>
where
    G: QemuAttemptProcessResourceGuard,
{
    fn clone(&self) -> Self {
        Self {
            state: Arc::clone(&self.state),
        }
    }
}

impl<G> Default for QemuHotForkWorldAuxiliaryResourceBroker<G>
where
    G: QemuAttemptProcessResourceGuard,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<G> QemuHotForkWorldAuxiliaryResourceBroker<G>
where
    G: QemuAttemptProcessResourceGuard,
{
    /// Creates an unbound per-worker auxiliary-resource broker.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(QemuHotForkWorldAuxiliaryBrokerState {
                next_token: 0,
                bound: None,
            })),
        }
    }

    pub(crate) fn bind(
        &self,
        resources: &QemuHotForkWorldResourceOwner<G>,
    ) -> Result<QemuHotForkWorldAuxiliaryResourceBinding<G>, QemuVmRealizationError> {
        let mut broker = self.state.lock().map_err(|_| {
            world_resource_error("hot-fork world auxiliary resource broker is poisoned")
        })?;
        if broker.bound.is_some() {
            return Err(world_resource_error(
                "hot-fork world auxiliary resource broker is already bound",
            ));
        }
        let token = broker.next_token.checked_add(1).ok_or_else(|| {
            world_resource_error("hot-fork world auxiliary resource broker token overflowed")
        })?;
        broker.next_token = token;
        broker.bound = Some((token, resources.auxiliary_resource_handle()));

        Ok(QemuHotForkWorldAuxiliaryResourceBinding {
            broker: Arc::clone(&self.state),
            token,
            bound: true,
        })
    }

    fn try_begin(
        &self,
        resources: AttemptResourceLimits,
        cancellation: &ExecutionCancellation,
    ) -> Result<Option<QemuHotForkWorldAuxiliaryGuard<G>>, QemuVmRealizationError> {
        let handle = {
            let broker = self.state.lock().map_err(|_| {
                world_resource_error("hot-fork world auxiliary resource broker is poisoned")
            })?;
            broker.bound.as_ref().map(|(_, handle)| handle.clone())
        };
        let Some(handle) = handle else {
            return Ok(None);
        };
        if handle.resources != resources || !handle.cancellation.same_incarnation(cancellation) {
            return Err(world_resource_error(
                "hot-fork world auxiliary request differs from the admitted attempt contract",
            ));
        }
        let state = handle.state.upgrade().ok_or_else(|| {
            world_resource_error("hot-fork world auxiliary aggregate owner was released")
        })?;
        auxiliary_guard_from_state(state, handle.resources, handle.cancellation).map(Some)
    }
}

pub(crate) struct QemuHotForkWorldAuxiliaryResourceBinding<G>
where
    G: QemuAttemptProcessResourceGuard,
{
    broker: Arc<Mutex<QemuHotForkWorldAuxiliaryBrokerState<G>>>,
    token: u64,
    bound: bool,
}

impl<G> QemuHotForkWorldAuxiliaryResourceBinding<G>
where
    G: QemuAttemptProcessResourceGuard,
{
    fn clear(&mut self) {
        if !self.bound {
            return;
        }
        match self.broker.lock() {
            Ok(mut broker) => {
                if matches!(broker.bound, Some((token, _)) if token == self.token) {
                    broker.bound = None;
                }
            }
            Err(poisoned) => {
                poisoned.into_inner().bound = None;
            }
        }
        self.bound = false;
    }
}

impl<G> Drop for QemuHotForkWorldAuxiliaryResourceBinding<G>
where
    G: QemuAttemptProcessResourceGuard,
{
    fn drop(&mut self) {
        self.clear();
    }
}

/// Resource factory selecting a retained hot-World lease or an ordinary fresh guard.
///
/// A bound broker always owns selection. An expired or incompatible binding
/// fails closed rather than allocating additional physical capacity. When no
/// hot lifecycle is pending, `fresh` installs the ordinary attempt guard.
pub(crate) struct QemuHotForkWorldAuxiliaryResourceFactory<F>
where
    F: QemuAttemptResourceGuardFactory,
    F::Guard: QemuAttemptProcessResourceGuard,
{
    broker: QemuHotForkWorldAuxiliaryResourceBroker<F::Guard>,
    fresh: F,
}

impl<F> QemuHotForkWorldAuxiliaryResourceFactory<F>
where
    F: QemuAttemptResourceGuardFactory,
    F::Guard: QemuAttemptProcessResourceGuard,
{
    /// Creates a factory over one worker broker and its ordinary fresh fallback.
    #[must_use]
    pub const fn new(broker: QemuHotForkWorldAuxiliaryResourceBroker<F::Guard>, fresh: F) -> Self {
        Self { broker, fresh }
    }
}

/// Process resource guard selected for one private replay lifecycle.
#[must_use = "finish the private replay resource guard or transfer it to quarantine"]
pub(crate) enum QemuHotForkWorldAuxiliaryResourceGuard<G>
where
    G: QemuAttemptProcessResourceGuard,
{
    /// Ordinary independently admitted fresh-attempt resources.
    Fresh(G),
    /// Sequential lease over the retained hot-World aggregate.
    Retained(QemuHotForkWorldAuxiliaryGuard<G>),
}

impl<F> QemuAttemptResourceGuardFactory for QemuHotForkWorldAuxiliaryResourceFactory<F>
where
    F: QemuAttemptResourceGuardFactory,
    F::Guard: QemuAttemptProcessResourceGuard,
{
    type Guard = QemuHotForkWorldAuxiliaryResourceGuard<F::Guard>;

    fn begin(
        &mut self,
        resources: AttemptResourceLimits,
        cancellation: ExecutionCancellation,
        selected_checkpoint: Option<crate::executor_supervisor::SelectedExactCheckpointRoot>,
    ) -> Result<Self::Guard, crate::crucible_qemu_session::QemuAttemptResourceGuardBeginFailure>
    {
        if selected_checkpoint.is_some() {
            return self
                .fresh
                .begin(resources, cancellation, selected_checkpoint)
                .map(QemuHotForkWorldAuxiliaryResourceGuard::Fresh);
        }
        match self.broker.try_begin(resources, &cancellation)? {
            Some(guard) => Ok(QemuHotForkWorldAuxiliaryResourceGuard::Retained(guard)),
            None => self
                .fresh
                .begin(resources, cancellation, None)
                .map(QemuHotForkWorldAuxiliaryResourceGuard::Fresh),
        }
    }
}

pub(super) fn auxiliary_guard_from_state<G>(
    state: Arc<Mutex<QemuHotForkWorldResourceState<G>>>,
    resources: AttemptResourceLimits,
    cancellation: ExecutionCancellation,
) -> Result<QemuHotForkWorldAuxiliaryGuard<G>, QemuVmRealizationError>
where
    G: QemuAttemptProcessResourceGuard,
{
    let mut registry = state
        .lock()
        .map_err(|_| world_resource_error("hot-fork world resource registry is poisoned"))?;
    if registry.terminal {
        return Err(world_resource_error(
            registry
                .terminal_failure
                .as_deref()
                .unwrap_or("hot-fork world resource owner is terminal"),
        ));
    }
    if !registry.lifecycle_launcher_required || !registry.lifecycle_launcher_finished {
        return Err(world_resource_error(
            "hot-fork world auxiliary lifecycle preceded primary launcher cleanup",
        ));
    }
    if registry.issued != registry.released {
        return Err(world_resource_error(
            "hot-fork world auxiliary lifecycle has an unfinished primary child target",
        ));
    }
    if registry.auxiliary_lifecycle_active {
        return Err(world_resource_error(
            "hot-fork world auxiliary lifecycle is already active",
        ));
    }
    let process_contract = registry
        .guard
        .child_process_contract()?
        .try_clone_for_attempt_generation()
        .map_err(|source| {
            world_resource_error(format!(
                "duplicate hot-fork world auxiliary process contract: {source}"
            ))
        })?;
    registry.auxiliary_lifecycle_active = true;
    drop(registry);

    Ok(QemuHotForkWorldAuxiliaryGuard {
        state,
        resources,
        cancellation,
        process_contract,
        finished: false,
    })
}

/// Linear process-resource lease for one private auxiliary lifecycle.
///
/// The duplicated process contract retains the aggregate containment identity,
/// but carries no run path or child identity. Each generation directory is
/// provisioned afresh through the underlying aggregate guard. The caller must
/// supply the distinct execution and process identities used to populate that
/// directory; this lease never receives source-template or publication
/// authority.
#[must_use = "finish the auxiliary lifecycle lease after exact child cleanup"]
pub(crate) struct QemuHotForkWorldAuxiliaryGuard<G>
where
    G: QemuAttemptProcessResourceGuard,
{
    state: Arc<Mutex<QemuHotForkWorldResourceState<G>>>,
    resources: AttemptResourceLimits,
    cancellation: ExecutionCancellation,
    process_contract: QemuChildProcessContract,
    finished: bool,
}

impl<G> fmt::Debug for QemuHotForkWorldAuxiliaryGuard<G>
where
    G: QemuAttemptProcessResourceGuard,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QemuHotForkWorldAuxiliaryGuard")
            .field("resources", &self.resources)
            .field("finished", &self.finished)
            .finish_non_exhaustive()
    }
}

impl<G> QemuAttemptOperationalBoundary for QemuHotForkWorldAuxiliaryGuard<G>
where
    G: QemuAttemptProcessResourceGuard,
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
        if self.finished || state.terminal || !state.auxiliary_lifecycle_active {
            return Err(world_resource_error(
                "hot-fork world auxiliary lifecycle is not operational",
            ));
        }
        state.guard.check_operational_boundary()
    }

    fn charge_execution_quantum(&mut self) -> Result<(), QemuVmRealizationError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| world_resource_error("hot-fork world resource registry is poisoned"))?;
        if self.finished || state.terminal || !state.auxiliary_lifecycle_active {
            return Err(world_resource_error(
                "hot-fork world auxiliary lifecycle is not operational",
            ));
        }
        state.guard.charge_execution_quantum()
    }
}

impl<G> QemuAttemptResourceGuard for QemuHotForkWorldAuxiliaryGuard<G>
where
    G: QemuAttemptProcessResourceGuard,
{
    fn finish(&mut self) -> Result<(), QemuVmRealizationError> {
        if self.finished {
            return Ok(());
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| world_resource_error("hot-fork world resource registry is poisoned"))?;
        if state.terminal || !state.auxiliary_lifecycle_active {
            return Err(world_resource_error(
                state
                    .terminal_failure
                    .as_deref()
                    .unwrap_or("hot-fork world auxiliary lifecycle is not active"),
            ));
        }
        state.auxiliary_lifecycle_active = false;
        self.finished = true;
        Ok(())
    }

    fn quarantine(&mut self) {
        if !self.finished {
            quarantine_world_state(&self.state);
            self.finished = true;
        }
    }
}

impl<G> QemuAttemptProcessResourceGuard for QemuHotForkWorldAuxiliaryGuard<G>
where
    G: QemuAttemptProcessResourceGuard,
{
    fn child_process_contract(&self) -> Result<&QemuChildProcessContract, QemuVmRealizationError> {
        let state = self
            .state
            .lock()
            .map_err(|_| world_resource_error("hot-fork world resource registry is poisoned"))?;
        if self.finished || state.terminal || !state.auxiliary_lifecycle_active {
            return Err(world_resource_error(
                "hot-fork world auxiliary lifecycle cannot lend its process contract",
            ));
        }
        drop(state);
        Ok(&self.process_contract)
    }

    fn prepare_generation_run_directory(
        &mut self,
        requirements: QemuLaunchResourceRequirements,
    ) -> Result<QemuPreparedRunDirectory, QemuVmRealizationError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| world_resource_error("hot-fork world resource registry is poisoned"))?;
        if self.finished || state.terminal || !state.auxiliary_lifecycle_active {
            return Err(world_resource_error(
                "hot-fork world auxiliary lifecycle cannot prepare a generation directory",
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
                    "hot-fork world auxiliary lifecycle retained an unreaped launch child",
                ));
            }
            Err(poisoned) => {
                let mut state = poisoned.into_inner();
                state.guard.retain_failed_launch_child(child);
                state.guard.quarantine();
                state.terminal = true;
                state.terminal_failure = Some(String::from(
                    "hot-fork world auxiliary resource registry was poisoned",
                ));
            }
        }
        self.finished = true;
    }
}

impl<G> Drop for QemuHotForkWorldAuxiliaryGuard<G>
where
    G: QemuAttemptProcessResourceGuard,
{
    fn drop(&mut self) {
        self.quarantine();
    }
}

impl<G> QemuAttemptOperationalBoundary for QemuHotForkWorldAuxiliaryResourceGuard<G>
where
    G: QemuAttemptProcessResourceGuard,
{
    fn resource_limits(&self) -> AttemptResourceLimits {
        match self {
            Self::Fresh(guard) => guard.resource_limits(),
            Self::Retained(guard) => guard.resource_limits(),
        }
    }

    fn cancellation(&self) -> &ExecutionCancellation {
        match self {
            Self::Fresh(guard) => guard.cancellation(),
            Self::Retained(guard) => guard.cancellation(),
        }
    }

    fn check_operational_boundary(&mut self) -> Result<(), QemuVmRealizationError> {
        match self {
            Self::Fresh(guard) => guard.check_operational_boundary(),
            Self::Retained(guard) => guard.check_operational_boundary(),
        }
    }

    fn charge_execution_quantum(&mut self) -> Result<(), QemuVmRealizationError> {
        match self {
            Self::Fresh(guard) => guard.charge_execution_quantum(),
            Self::Retained(guard) => guard.charge_execution_quantum(),
        }
    }
}

impl<G> QemuAttemptResourceGuard for QemuHotForkWorldAuxiliaryResourceGuard<G>
where
    G: QemuAttemptProcessResourceGuard,
{
    fn finish(&mut self) -> Result<(), QemuVmRealizationError> {
        match self {
            Self::Fresh(guard) => guard.finish(),
            Self::Retained(guard) => guard.finish(),
        }
    }

    fn quarantine(&mut self) {
        match self {
            Self::Fresh(guard) => guard.quarantine(),
            Self::Retained(guard) => guard.quarantine(),
        }
    }
}

impl<G> QemuAttemptProcessResourceGuard for QemuHotForkWorldAuxiliaryResourceGuard<G>
where
    G: QemuAttemptProcessResourceGuard,
{
    fn child_process_contract(&self) -> Result<&QemuChildProcessContract, QemuVmRealizationError> {
        match self {
            Self::Fresh(guard) => guard.child_process_contract(),
            Self::Retained(guard) => guard.child_process_contract(),
        }
    }

    fn prepare_generation_run_directory(
        &mut self,
        requirements: QemuLaunchResourceRequirements,
    ) -> Result<QemuPreparedRunDirectory, QemuVmRealizationError> {
        match self {
            Self::Fresh(guard) => guard.prepare_generation_run_directory(requirements),
            Self::Retained(guard) => guard.prepare_generation_run_directory(requirements),
        }
    }

    fn retain_failed_launch_child(&mut self, child: QemuNodeChild) {
        match self {
            Self::Fresh(guard) => guard.retain_failed_launch_child(child),
            Self::Retained(guard) => guard.retain_failed_launch_child(child),
        }
    }
}
