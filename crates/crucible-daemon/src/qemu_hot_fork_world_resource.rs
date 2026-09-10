//! Aggregate target-resource ownership for one hot-fork child world.
//!
//! A campaign branch owns one attempt-wide CPU, memory, writable-storage,
//! cancellation, and execution-quantum contract even when its World contains
//! several QEMU children. This module keeps that guard indivisible while
//! issuing one linear node target for each child. Per-node reconciliation may
//! attest that its exact child is gone, but only the aggregate owner can release
//! the underlying attempt guard after every issued target has finished.

use std::collections::BTreeSet;
use std::fmt;
use std::sync::{Arc, Mutex, Weak};

// crucible-lint: allow host-nondeterminism-state -- exact node generations index operational resource ownership, not scheduler decisions or guest time.
use crucible_api::ProductionVmNodeGeneration;
use crucible_campaign::AttemptResourceLimits;
use crucible_qemu::{
    QemuChildProcessContract, QemuLaunchResourceRequirements, QemuNodeChild,
    QemuPreparedRunDirectory, QemuVmRealizationError,
};

use crate::{
    ExecutionCancellation, MAX_QEMU_ATTEMPT_GENERATION_NODES, QemuAttemptOperationalBoundary,
    QemuAttemptProcessResourceGuard, QemuAttemptResourceGuard, QemuAttemptResourceGuardFactory,
};

#[cfg(feature = "destructive-recovery-faults")]
const DESTRUCTIVE_RECOVERY_TRIGGER_ENVIRONMENT: &str = "CRUCIBLE_DESTRUCTIVE_RECOVERY_TRIGGER";
#[cfg(feature = "destructive-recovery-faults")]
const WORLD_FORK_ONE_VM_FAILURE_TRIGGER: &str =
    "crucible.destructive-recovery.world-fork-one-vm-failure";

struct QemuHotForkWorldAuxiliaryResourceHandle<G>
where
    G: QemuAttemptProcessResourceGuard,
{
    state: Weak<Mutex<QemuHotForkWorldResourceState<G>>>,
    resources: AttemptResourceLimits,
    cancellation: ExecutionCancellation,
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
pub struct QemuHotForkWorldAuxiliaryResourceBroker<G>
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
pub struct QemuHotForkWorldAuxiliaryResourceFactory<F>
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

    /// Returns the per-worker auxiliary-resource broker.
    #[must_use]
    pub const fn broker(&self) -> &QemuHotForkWorldAuxiliaryResourceBroker<F::Guard> {
        &self.broker
    }

    /// Returns the ordinary fresh resource factory.
    #[must_use]
    pub const fn fresh(&self) -> &F {
        &self.fresh
    }
}

/// Process resource guard selected for one private replay lifecycle.
#[must_use = "finish the private replay resource guard or transfer it to quarantine"]
pub enum QemuHotForkWorldAuxiliaryResourceGuard<G>
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
    ) -> Result<Self::Guard, QemuVmRealizationError> {
        match self.broker.try_begin(resources, &cancellation)? {
            Some(guard) => Ok(QemuHotForkWorldAuxiliaryResourceGuard::Retained(guard)),
            None => self
                .fresh
                .begin(resources, cancellation)
                .map(QemuHotForkWorldAuxiliaryResourceGuard::Fresh),
        }
    }
}

struct QemuHotForkWorldResourceState<G>
where
    G: QemuAttemptResourceGuard,
{
    guard: G,
    maximum_nodes: usize,
    issued: BTreeSet<ProductionVmNodeGeneration>,
    released: BTreeSet<ProductionVmNodeGeneration>,
    lifecycle_launcher_required: bool,
    lifecycle_launcher_finished: bool,
    auxiliary_lifecycle_active: bool,
    terminal: bool,
    terminal_failure: Option<String>,
}

/// Indivisible attempt-resource owner shared by every child in one forked World.
#[must_use = "finish the complete hot-fork world owner or transfer it to quarantine"]
pub struct QemuHotForkWorldResourceOwner<G>
where
    G: QemuAttemptResourceGuard,
{
    state: Arc<Mutex<QemuHotForkWorldResourceState<G>>>,
    resources: AttemptResourceLimits,
    cancellation: ExecutionCancellation,
}

impl<G> fmt::Debug for QemuHotForkWorldResourceOwner<G>
where
    G: QemuAttemptResourceGuard,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut output = formatter.debug_struct("QemuHotForkWorldResourceOwner");
        output.field("resources", &self.resources);
        match self.state.lock() {
            Ok(state) => output
                .field("maximum_nodes", &state.maximum_nodes)
                .field("issued", &state.issued.len())
                .field("released", &state.released.len())
                .field(
                    "auxiliary_lifecycle_active",
                    &state.auxiliary_lifecycle_active,
                )
                .field("terminal", &state.terminal),
            Err(_) => output.field("state", &"poisoned"),
        };
        output.finish_non_exhaustive()
    }
}

impl<G> QemuHotForkWorldResourceOwner<G>
where
    G: QemuAttemptResourceGuard,
{
    /// Seals one installed attempt guard behind a bounded World node registry.
    ///
    /// # Errors
    ///
    /// Returns an executor error and quarantines `guard` when `maximum_nodes`
    /// is zero or exceeds [`MAX_QEMU_ATTEMPT_GENERATION_NODES`].
    pub fn new(mut guard: G, maximum_nodes: usize) -> Result<Self, QemuVmRealizationError> {
        if maximum_nodes == 0 || maximum_nodes > MAX_QEMU_ATTEMPT_GENERATION_NODES {
            guard.quarantine();
            return Err(world_resource_error(format!(
                "hot-fork world node bound {maximum_nodes} is outside 1..={MAX_QEMU_ATTEMPT_GENERATION_NODES}"
            )));
        }
        let resources = guard.resource_limits();
        let cancellation = guard.cancellation().clone();
        Ok(Self {
            state: Arc::new(Mutex::new(QemuHotForkWorldResourceState {
                guard,
                maximum_nodes,
                issued: BTreeSet::new(),
                released: BTreeSet::new(),
                lifecycle_launcher_required: false,
                lifecycle_launcher_finished: false,
                auxiliary_lifecycle_active: false,
                terminal: false,
                terminal_failure: None,
            })),
            resources,
            cancellation,
        })
    }

    /// Returns the exact attempt-wide hard-resource basis.
    #[must_use]
    pub const fn resource_limits(&self) -> AttemptResourceLimits {
        self.resources
    }

    /// Returns the exact process-local cancellation incarnation.
    #[must_use]
    pub const fn cancellation(&self) -> &ExecutionCancellation {
        &self.cancellation
    }

    /// Reserves one exact child generation before its QEMU fork transaction.
    ///
    /// A caller must either install the returned target into the successful
    /// child reconciliation owner or roll it back after an explicit pre-fork
    /// rejection. Dropping an unfinished target quarantines the complete World.
    ///
    /// # Errors
    ///
    /// Returns an executor error after terminal cleanup, registry poison,
    /// duplicate generation, or distinct-node bound exhaustion.
    pub(crate) fn reserve_node(
        &mut self,
        identity: ProductionVmNodeGeneration,
    ) -> Result<QemuHotForkWorldNodeTarget<G>, QemuVmRealizationError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| world_resource_error("hot-fork world resource registry is poisoned"))?;
        if state.terminal {
            return Err(world_resource_error(
                state
                    .terminal_failure
                    .as_deref()
                    .unwrap_or("hot-fork world resource owner is terminal"),
            ));
        }
        if state.lifecycle_launcher_finished {
            return Err(world_resource_error(
                "hot-fork world primary node registry is already sealed",
            ));
        }
        if state
            .issued
            .iter()
            .any(|issued| issued.node() == identity.node())
        {
            return Err(world_resource_error(format!(
                "hot-fork world already reserved node `{}`",
                identity.node().name
            )));
        }
        if state.issued.len() >= state.maximum_nodes {
            return Err(world_resource_error(format!(
                "hot-fork world node bound {} is exhausted",
                state.maximum_nodes
            )));
        }
        #[cfg(feature = "destructive-recovery-faults")]
        if !state.issued.is_empty() && world_fork_one_vm_failure_requested() {
            return Err(world_resource_error(
                "fault-injected failure while reserving the next hot-fork world VM",
            ));
        }
        state.issued.insert(identity.clone());
        drop(state);
        Ok(QemuHotForkWorldNodeTarget {
            state: Arc::clone(&self.state),
            identity,
            resources: self.resources,
            cancellation: self.cancellation.clone(),
            released: false,
        })
    }

    /// Runs one launch-only operation against the still-indivisible guard.
    ///
    /// # Errors
    ///
    /// Returns an executor error after terminal cleanup or registry poison.
    pub(crate) fn with_guard_mut<T>(
        &mut self,
        operation: impl FnOnce(&mut G) -> T,
    ) -> Result<T, QemuVmRealizationError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| world_resource_error("hot-fork world resource registry is poisoned"))?;
        if state.terminal {
            return Err(world_resource_error(
                state
                    .terminal_failure
                    .as_deref()
                    .unwrap_or("hot-fork world resource owner is terminal"),
            ));
        }
        if state.auxiliary_lifecycle_active {
            return Err(world_resource_error(
                "hot-fork world auxiliary lifecycle is active",
            ));
        }
        Ok(operation(&mut state.guard))
    }

    /// Mints the shared guard used by the adopted production lifecycle launcher.
    ///
    /// The returned guard owns a duplicated process contract while every mutable
    /// operation remains serialized through the aggregate owner. Its successful
    /// `finish` records that all lifecycle-created generation leases were
    /// released, but deliberately leaves aggregate enforcement installed until
    /// post-publication reconciliation finishes every adopted child.
    ///
    /// # Errors
    ///
    /// Returns an executor error after terminal cleanup, a repeated launcher
    /// handoff, registry poison, or process-contract duplication failure.
    pub(crate) fn lifecycle_guard(
        &mut self,
    ) -> Result<QemuHotForkWorldLifecycleGuard<G>, QemuVmRealizationError>
    where
        G: QemuAttemptProcessResourceGuard,
    {
        let mut state = self
            .state
            .lock()
            .map_err(|_| world_resource_error("hot-fork world resource registry is poisoned"))?;
        if state.terminal {
            return Err(world_resource_error(
                state
                    .terminal_failure
                    .as_deref()
                    .unwrap_or("hot-fork world resource owner is terminal"),
            ));
        }
        if state.lifecycle_launcher_required {
            return Err(world_resource_error(
                "hot-fork world lifecycle launcher was already issued",
            ));
        }
        let process_contract = state
            .guard
            .child_process_contract()?
            .try_clone_for_attempt_generation()
            .map_err(|source| {
                world_resource_error(format!(
                    "duplicate hot-fork world lifecycle process contract: {source}"
                ))
            })?;
        state.lifecycle_launcher_required = true;
        drop(state);

        Ok(QemuHotForkWorldLifecycleGuard {
            state: Arc::clone(&self.state),
            resources: self.resources,
            cancellation: self.cancellation.clone(),
            process_contract,
            finished: false,
        })
    }

    /// Mints a sequential private lifecycle lease from the retained aggregate.
    ///
    /// The aggregate remains the sole owner of physical resources and final
    /// release authority. The auxiliary lease receives a duplicated process
    /// contract and serial access to the same cancellation, execution-quantum,
    /// run-directory, and host-resource state. A new lease is available only
    /// after every primary node target and the primary lifecycle launcher have
    /// attested cleanup.
    ///
    /// # Errors
    ///
    /// Returns an executor error when the primary lifecycle is incomplete, a
    /// prior auxiliary lease remains active, the owner is terminal or poisoned,
    /// or the process contract cannot be duplicated.
    pub fn auxiliary_lifecycle_guard(
        &mut self,
    ) -> Result<QemuHotForkWorldAuxiliaryGuard<G>, QemuVmRealizationError>
    where
        G: QemuAttemptProcessResourceGuard,
    {
        auxiliary_guard_from_state(
            Arc::clone(&self.state),
            self.resources,
            self.cancellation.clone(),
        )
    }

    fn auxiliary_resource_handle(&self) -> QemuHotForkWorldAuxiliaryResourceHandle<G>
    where
        G: QemuAttemptProcessResourceGuard,
    {
        QemuHotForkWorldAuxiliaryResourceHandle {
            state: Arc::downgrade(&self.state),
            resources: self.resources,
            cancellation: self.cancellation.clone(),
        }
    }

    /// Releases aggregate enforcement after every exact child target finished.
    ///
    /// The method is idempotent after success. An incomplete target set
    /// quarantines the underlying guard rather than claiming resource release.
    ///
    /// # Errors
    ///
    /// Returns an executor error when a target remains live, the registry is
    /// poisoned, or the underlying guard cannot attest final release.
    pub fn finish(&mut self) -> Result<(), QemuVmRealizationError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| world_resource_error("hot-fork world resource registry is poisoned"))?;
        if state.terminal {
            return state
                .terminal_failure
                .as_ref()
                .map_or(Ok(()), |message| Err(world_resource_error(message.clone())));
        }
        if state.issued != state.released {
            let message =
                String::from("hot-fork world aggregate release has an unfinished child target");
            state.guard.quarantine();
            state.terminal = true;
            state.terminal_failure = Some(message.clone());
            return Err(world_resource_error(message));
        }
        if state.lifecycle_launcher_required && !state.lifecycle_launcher_finished {
            let message = String::from(
                "hot-fork world aggregate release preceded lifecycle launcher cleanup",
            );
            state.guard.quarantine();
            state.terminal = true;
            state.terminal_failure = Some(message.clone());
            return Err(world_resource_error(message));
        }
        if state.auxiliary_lifecycle_active {
            let message =
                String::from("hot-fork world aggregate release has an active auxiliary lifecycle");
            state.guard.quarantine();
            state.terminal = true;
            state.terminal_failure = Some(message.clone());
            return Err(world_resource_error(message));
        }
        let result = state.guard.finish();
        state.terminal = true;
        if let Err(error) = &result {
            state.terminal_failure = Some(error.to_string());
        }
        result
    }

    /// Transfers the complete aggregate guard to fail-closed quarantine.
    pub fn quarantine(&mut self) {
        quarantine_world_state(&self.state);
    }
}

fn auxiliary_guard_from_state<G>(
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

/// Shared process/storage guard for generations created after world adoption.
///
/// This guard is installed into [`crate::QemuAttemptGenerationResourceOwner`].
/// Its normal finish proves that the lifecycle released all of its generation
/// leases while deferring aggregate release to [`QemuHotForkWorldResourceOwner`].
pub(crate) struct QemuHotForkWorldLifecycleGuard<G>
where
    G: QemuAttemptProcessResourceGuard,
{
    state: Arc<Mutex<QemuHotForkWorldResourceState<G>>>,
    resources: AttemptResourceLimits,
    cancellation: ExecutionCancellation,
    process_contract: QemuChildProcessContract,
    finished: bool,
}

impl<G> QemuAttemptOperationalBoundary for QemuHotForkWorldLifecycleGuard<G>
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
        if self.finished || state.terminal {
            return Err(world_resource_error(
                "hot-fork world lifecycle launcher is not operational",
            ));
        }
        state.guard.check_operational_boundary()
    }

    fn charge_execution_quantum(&mut self) -> Result<(), QemuVmRealizationError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| world_resource_error("hot-fork world resource registry is poisoned"))?;
        if self.finished || state.terminal {
            return Err(world_resource_error(
                "hot-fork world lifecycle launcher is not operational",
            ));
        }
        state.guard.charge_execution_quantum()
    }
}

impl<G> QemuAttemptResourceGuard for QemuHotForkWorldLifecycleGuard<G>
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
        if state.terminal {
            return Err(world_resource_error(
                state
                    .terminal_failure
                    .as_deref()
                    .unwrap_or("hot-fork world resource owner is terminal"),
            ));
        }
        state.lifecycle_launcher_finished = true;
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

impl<G> QemuAttemptProcessResourceGuard for QemuHotForkWorldLifecycleGuard<G>
where
    G: QemuAttemptProcessResourceGuard,
{
    fn child_process_contract(&self) -> Result<&QemuChildProcessContract, QemuVmRealizationError> {
        let state = self
            .state
            .lock()
            .map_err(|_| world_resource_error("hot-fork world resource registry is poisoned"))?;
        if self.finished || state.terminal {
            return Err(world_resource_error(
                "hot-fork world lifecycle launcher cannot lend its process contract",
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
        if self.finished || state.terminal {
            return Err(world_resource_error(
                "hot-fork world lifecycle launcher cannot prepare a generation directory",
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
                    "hot-fork world lifecycle retained an unreaped launch child",
                ));
            }
            Err(poisoned) => {
                let mut state = poisoned.into_inner();
                state.guard.retain_failed_launch_child(child);
                state.guard.quarantine();
                state.terminal = true;
                state.terminal_failure = Some(String::from(
                    "hot-fork world lifecycle resource registry was poisoned",
                ));
            }
        }
        self.finished = true;
    }
}

impl<G> Drop for QemuHotForkWorldLifecycleGuard<G>
where
    G: QemuAttemptProcessResourceGuard,
{
    fn drop(&mut self) {
        self.quarantine();
    }
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
pub struct QemuHotForkWorldAuxiliaryGuard<G>
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

impl<G> Drop for QemuHotForkWorldResourceOwner<G>
where
    G: QemuAttemptResourceGuard,
{
    fn drop(&mut self) {
        quarantine_world_state(&self.state);
    }
}

/// Linear target-resource share for one exact child generation.
///
/// This value can check and charge the shared attempt contract, but it cannot
/// release aggregate enforcement. Its [`QemuAttemptResourceGuard::finish`]
/// implementation records only that this exact child completed target cleanup;
/// the owning [`QemuHotForkWorldResourceOwner`] performs final release.
#[must_use = "finish the hot-fork node target only after exact child reap"]
pub struct QemuHotForkWorldNodeTarget<G>
where
    G: QemuAttemptResourceGuard,
{
    state: Arc<Mutex<QemuHotForkWorldResourceState<G>>>,
    identity: ProductionVmNodeGeneration,
    resources: AttemptResourceLimits,
    cancellation: ExecutionCancellation,
    released: bool,
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

fn quarantine_world_state<G>(state: &Arc<Mutex<QemuHotForkWorldResourceState<G>>>)
where
    G: QemuAttemptResourceGuard,
{
    match state.lock() {
        Ok(mut state) => {
            if !state.terminal {
                state.guard.quarantine();
                state.terminal = true;
                state.terminal_failure = Some(String::from(
                    "hot-fork world resources were transferred to quarantine",
                ));
            }
        }
        Err(poisoned) => {
            let mut state = poisoned.into_inner();
            if !state.terminal {
                state.guard.quarantine();
                state.terminal = true;
                state.terminal_failure = Some(String::from(
                    "hot-fork world resource registry was poisoned and quarantined",
                ));
            }
        }
    }
}

fn world_resource_error(message: impl Into<String>) -> QemuVmRealizationError {
    QemuVmRealizationError::Executor {
        operation: "manage aggregate hot-fork world resources",
        message: message.into(),
    }
}

#[cfg(feature = "destructive-recovery-faults")]
fn world_fork_one_vm_failure_requested() -> bool {
    std::env::var_os(DESTRUCTIVE_RECOVERY_TRIGGER_ENVIRONMENT).as_deref()
        == Some(std::ffi::OsStr::new(WORLD_FORK_ONE_VM_FAILURE_TRIGGER))
}

#[cfg(test)]
mod tests {
    // crucible-lint: allow panic-shortcut -- fixture construction and expected success must fail the test on error.
    #![allow(clippy::expect_used)]

    use std::fs::File;
    use std::os::unix::net::UnixStream;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use crucible::NodeId;
    use tempfile::TempDir;

    use super::*;
    use crate::QemuExecutionQuantumCounter;

    #[derive(Debug)]
    struct FakeGuard {
        resources: AttemptResourceLimits,
        cancellation: ExecutionCancellation,
        counter: QemuExecutionQuantumCounter,
        process_contract: QemuChildProcessContract,
        finishes: Arc<AtomicUsize>,
        quarantines: Arc<AtomicUsize>,
        active_capacity: Option<Arc<AtomicUsize>>,
        run_root: TempDir,
        next_generation: usize,
        terminal: bool,
    }

    impl QemuAttemptOperationalBoundary for FakeGuard {
        fn resource_limits(&self) -> AttemptResourceLimits {
            self.resources
        }

        fn cancellation(&self) -> &ExecutionCancellation {
            &self.cancellation
        }

        fn check_operational_boundary(&mut self) -> Result<(), QemuVmRealizationError> {
            if self.cancellation.is_canceled() {
                Err(QemuVmRealizationError::Canceled {
                    operation: "check fake world resources",
                })
            } else {
                Ok(())
            }
        }

        fn charge_execution_quantum(&mut self) -> Result<(), QemuVmRealizationError> {
            self.check_operational_boundary()?;
            self.counter.charge()
        }
    }

    impl QemuAttemptResourceGuard for FakeGuard {
        fn finish(&mut self) -> Result<(), QemuVmRealizationError> {
            if self.terminal {
                return Ok(());
            }
            self.finishes.fetch_add(1, Ordering::AcqRel);
            if let Some(active) = &self.active_capacity {
                active.fetch_sub(1, Ordering::AcqRel);
            }
            self.terminal = true;
            Ok(())
        }

        fn quarantine(&mut self) {
            if self.terminal {
                return;
            }
            self.quarantines.fetch_add(1, Ordering::AcqRel);
            if let Some(active) = &self.active_capacity {
                active.fetch_sub(1, Ordering::AcqRel);
            }
            self.terminal = true;
        }
    }

    impl QemuAttemptProcessResourceGuard for FakeGuard {
        fn child_process_contract(
            &self,
        ) -> Result<&QemuChildProcessContract, QemuVmRealizationError> {
            Ok(&self.process_contract)
        }

        fn prepare_generation_run_directory(
            &mut self,
            requirements: QemuLaunchResourceRequirements,
        ) -> Result<QemuPreparedRunDirectory, QemuVmRealizationError> {
            let generation = self
                .run_root
                .path()
                .join(format!("generation-{:03}", self.next_generation));
            self.next_generation += 1;
            std::fs::create_dir(&generation)
                .map_err(|error| world_resource_error(error.to_string()))?;
            File::create(generation.join(crucible_qemu::DEFAULT_VMSTATE_FILE_NAME))
                .map_err(|error| world_resource_error(error.to_string()))?;
            if requirements.has_root_overlay() {
                File::create(generation.join(crucible_qemu::DEFAULT_ROOT_OVERLAY_FILE_NAME))
                    .map_err(|error| world_resource_error(error.to_string()))?;
            }
            QemuPreparedRunDirectory::open_for_test_requirements(
                requirements,
                generation,
                &self.process_contract,
            )
            .map_err(|error| world_resource_error(error.to_string()))
        }

        fn retain_failed_launch_child(&mut self, _child: QemuNodeChild) {}
    }

    fn resources() -> AttemptResourceLimits {
        AttemptResourceLimits::new(1, 1024 * 1024, 1024 * 1024 * 1024, 2).expect("resource limits")
    }

    fn identity(name: &str, generation: u64) -> ProductionVmNodeGeneration {
        ProductionVmNodeGeneration::new(
            NodeId {
                name: name.to_owned(),
            },
            generation,
        )
        .expect("node generation")
    }

    fn guard(finishes: Arc<AtomicUsize>, quarantines: Arc<AtomicUsize>) -> FakeGuard {
        let resources = resources();
        let (cgroup_procs, _cgroup_peer) =
            UnixStream::pair().expect("fake cgroup process descriptor");
        let (cancellation_event, _cancellation_peer) =
            UnixStream::pair().expect("fake cancellation descriptor");
        FakeGuard {
            resources,
            cancellation: ExecutionCancellation::default(),
            counter: QemuExecutionQuantumCounter::new(resources),
            process_contract: QemuChildProcessContract::from_unvalidated_test_descriptors(
                cgroup_procs.into(),
                cancellation_event.into(),
                resources.maximum_vcpus(),
                resources.maximum_resident_bytes(),
                resources.maximum_disk_bytes(),
            ),
            finishes,
            quarantines,
            active_capacity: None,
            run_root: TempDir::new().expect("fake run root"),
            next_generation: 0,
            terminal: false,
        }
    }

    struct OneCapacityGuardFactory {
        active: Arc<AtomicUsize>,
        begins: Arc<AtomicUsize>,
        finishes: Arc<AtomicUsize>,
        quarantines: Arc<AtomicUsize>,
    }

    impl QemuAttemptResourceGuardFactory for OneCapacityGuardFactory {
        type Guard = FakeGuard;

        fn begin(
            &mut self,
            resources: AttemptResourceLimits,
            cancellation: ExecutionCancellation,
        ) -> Result<Self::Guard, QemuVmRealizationError> {
            if self
                .active
                .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                return Err(world_resource_error(
                    "one-capacity resource factory is occupied",
                ));
            }
            self.begins.fetch_add(1, Ordering::AcqRel);
            let mut admitted = guard(Arc::clone(&self.finishes), Arc::clone(&self.quarantines));
            admitted.resources = resources;
            admitted.cancellation = cancellation;
            admitted.counter = QemuExecutionQuantumCounter::new(resources);
            admitted.active_capacity = Some(Arc::clone(&self.active));
            Ok(admitted)
        }
    }

    fn finish_primary_lifecycle(owner: &mut QemuHotForkWorldResourceOwner<FakeGuard>, node: &str) {
        let mut target = owner
            .reserve_node(identity(node, 1))
            .expect("primary target");
        QemuAttemptResourceGuard::finish(&mut target).expect("finish primary target");
        let mut lifecycle = owner.lifecycle_guard().expect("primary lifecycle guard");
        QemuAttemptResourceGuard::finish(&mut lifecycle).expect("finish primary lifecycle");
    }

    #[test]
    fn aggregate_release_waits_for_every_exact_node_target() {
        let finishes = Arc::new(AtomicUsize::new(0));
        let quarantines = Arc::new(AtomicUsize::new(0));
        let mut owner = QemuHotForkWorldResourceOwner::new(
            guard(Arc::clone(&finishes), Arc::clone(&quarantines)),
            2,
        )
        .expect("world owner");
        let mut first = owner.reserve_node(identity("first", 4)).expect("first");
        let mut second = owner.reserve_node(identity("second", 9)).expect("second");

        first
            .charge_execution_quantum()
            .expect("shared quantum one");
        second
            .charge_execution_quantum()
            .expect("shared quantum two");
        assert!(second.charge_execution_quantum().is_err());
        QemuAttemptResourceGuard::finish(&mut first).expect("finish first");
        QemuAttemptResourceGuard::finish(&mut second).expect("finish second");
        owner.finish().expect("finish aggregate");

        assert_eq!(finishes.load(Ordering::Acquire), 1);
        assert_eq!(quarantines.load(Ordering::Acquire), 0);
    }

    #[test]
    fn unfinished_or_duplicate_node_fails_closed() {
        let finishes = Arc::new(AtomicUsize::new(0));
        let quarantines = Arc::new(AtomicUsize::new(0));
        let mut owner = QemuHotForkWorldResourceOwner::new(
            guard(Arc::clone(&finishes), Arc::clone(&quarantines)),
            1,
        )
        .expect("world owner");
        let target = owner.reserve_node(identity("node", 3)).expect("node");
        assert!(owner.reserve_node(identity("node", 4)).is_err());
        assert!(owner.finish().is_err());
        drop(target);

        assert_eq!(finishes.load(Ordering::Acquire), 0);
        assert_eq!(quarantines.load(Ordering::Acquire), 1);
    }

    #[test]
    fn explicit_no_child_rollback_reopens_the_exact_slot() {
        let finishes = Arc::new(AtomicUsize::new(0));
        let quarantines = Arc::new(AtomicUsize::new(0));
        let mut owner = QemuHotForkWorldResourceOwner::new(
            guard(Arc::clone(&finishes), Arc::clone(&quarantines)),
            1,
        )
        .expect("world owner");
        owner
            .reserve_node(identity("node", 3))
            .expect("reserve")
            .abort_without_child()
            .expect("rollback");
        let mut retried = owner.reserve_node(identity("node", 3)).expect("retry");
        QemuAttemptResourceGuard::finish(&mut retried).expect("finish retry");
        owner.finish().expect("finish aggregate");

        assert_eq!(finishes.load(Ordering::Acquire), 1);
        assert_eq!(quarantines.load(Ordering::Acquire), 0);
    }

    #[test]
    fn partial_world_rejection_rolls_back_only_the_unforked_node() {
        let finishes = Arc::new(AtomicUsize::new(0));
        let quarantines = Arc::new(AtomicUsize::new(0));
        let mut owner = QemuHotForkWorldResourceOwner::new(
            guard(Arc::clone(&finishes), Arc::clone(&quarantines)),
            2,
        )
        .expect("world owner");
        let mut first = owner.reserve_node(identity("first", 4)).expect("first");
        owner
            .reserve_node(identity("second", 9))
            .expect("second reservation")
            .abort_without_child()
            .expect("explicit no-child rollback");

        let mut retried = owner
            .reserve_node(identity("second", 9))
            .expect("second retry");
        QemuAttemptResourceGuard::finish(&mut first).expect("finish first");
        QemuAttemptResourceGuard::finish(&mut retried).expect("finish retried second");
        owner.finish().expect("finish aggregate");

        assert_eq!(finishes.load(Ordering::Acquire), 1);
        assert_eq!(quarantines.load(Ordering::Acquire), 0);
    }

    #[test]
    fn partial_world_ambiguous_failure_quarantines_the_aggregate() {
        let finishes = Arc::new(AtomicUsize::new(0));
        let quarantines = Arc::new(AtomicUsize::new(0));
        let mut owner = QemuHotForkWorldResourceOwner::new(
            guard(Arc::clone(&finishes), Arc::clone(&quarantines)),
            2,
        )
        .expect("world owner");
        let mut first = owner.reserve_node(identity("first", 4)).expect("first");
        let ambiguous = owner.reserve_node(identity("second", 9)).expect("second");
        QemuAttemptResourceGuard::finish(&mut first).expect("finish first");

        drop(ambiguous);
        assert!(owner.finish().is_err());
        assert_eq!(finishes.load(Ordering::Acquire), 0);
        assert_eq!(quarantines.load(Ordering::Acquire), 1);
    }

    #[test]
    fn auxiliary_lifecycle_requires_complete_primary_cleanup() {
        let finishes = Arc::new(AtomicUsize::new(0));
        let quarantines = Arc::new(AtomicUsize::new(0));
        let mut owner = QemuHotForkWorldResourceOwner::new(
            guard(Arc::clone(&finishes), Arc::clone(&quarantines)),
            1,
        )
        .expect("world owner");
        assert!(owner.auxiliary_lifecycle_guard().is_err());

        let mut target = owner
            .reserve_node(identity("node", 1))
            .expect("primary target");
        let mut lifecycle = owner.lifecycle_guard().expect("primary lifecycle guard");
        QemuAttemptResourceGuard::finish(&mut lifecycle).expect("finish primary lifecycle");
        assert!(owner.auxiliary_lifecycle_guard().is_err());

        QemuAttemptResourceGuard::finish(&mut target).expect("finish primary target");
        let mut auxiliary = owner
            .auxiliary_lifecycle_guard()
            .expect("complete primary admits auxiliary lifecycle");
        QemuAttemptResourceGuard::finish(&mut auxiliary).expect("finish auxiliary lifecycle");
        owner.finish().expect("finish aggregate");

        assert_eq!(finishes.load(Ordering::Acquire), 1);
        assert_eq!(quarantines.load(Ordering::Acquire), 0);
    }

    #[test]
    fn auxiliary_lifecycle_is_a_single_reusable_sequential_lease() {
        let finishes = Arc::new(AtomicUsize::new(0));
        let quarantines = Arc::new(AtomicUsize::new(0));
        let mut owner = QemuHotForkWorldResourceOwner::new(
            guard(Arc::clone(&finishes), Arc::clone(&quarantines)),
            1,
        )
        .expect("world owner");
        finish_primary_lifecycle(&mut owner, "node");

        let mut first = owner
            .auxiliary_lifecycle_guard()
            .expect("first auxiliary lifecycle");
        assert!(owner.auxiliary_lifecycle_guard().is_err());
        QemuAttemptResourceGuard::finish(&mut first).expect("finish first auxiliary lifecycle");

        let mut second = owner
            .auxiliary_lifecycle_guard()
            .expect("second sequential auxiliary lifecycle");
        QemuAttemptResourceGuard::finish(&mut second).expect("finish second auxiliary lifecycle");
        owner.finish().expect("finish aggregate");
        owner.finish().expect("aggregate finish is idempotent");

        assert_eq!(finishes.load(Ordering::Acquire), 1);
        assert_eq!(quarantines.load(Ordering::Acquire), 0);
    }

    #[test]
    fn auxiliary_lifecycle_shares_one_capacity_quantum_and_cancellation() {
        let finishes = Arc::new(AtomicUsize::new(0));
        let quarantines = Arc::new(AtomicUsize::new(0));
        let mut owner = QemuHotForkWorldResourceOwner::new(
            guard(Arc::clone(&finishes), Arc::clone(&quarantines)),
            1,
        )
        .expect("world owner");
        let mut target = owner
            .reserve_node(identity("node", 1))
            .expect("primary target");
        target.charge_execution_quantum().expect("primary quantum");
        QemuAttemptResourceGuard::finish(&mut target).expect("finish primary target");
        let mut lifecycle = owner.lifecycle_guard().expect("primary lifecycle guard");
        QemuAttemptResourceGuard::finish(&mut lifecycle).expect("finish primary lifecycle");

        let mut auxiliary = owner
            .auxiliary_lifecycle_guard()
            .expect("auxiliary lifecycle");
        assert_eq!(auxiliary.resource_limits(), owner.resource_limits());
        assert!(
            auxiliary
                .cancellation()
                .same_incarnation(owner.cancellation())
        );
        auxiliary
            .charge_execution_quantum()
            .expect("remaining shared quantum");
        assert!(auxiliary.charge_execution_quantum().is_err());

        owner.cancellation().cancel_for_test();
        assert!(auxiliary.check_operational_boundary().is_err());
        assert_eq!(finishes.load(Ordering::Acquire), 0);
        assert_eq!(quarantines.load(Ordering::Acquire), 0);
        QemuAttemptResourceGuard::finish(&mut auxiliary).expect("finish canceled auxiliary");
        owner.finish().expect("finish canceled aggregate");

        assert_eq!(finishes.load(Ordering::Acquire), 1);
        assert_eq!(quarantines.load(Ordering::Acquire), 0);
    }

    #[test]
    fn bound_replay_factory_reuses_one_capacity_with_fresh_private_directories() {
        let active = Arc::new(AtomicUsize::new(0));
        let begins = Arc::new(AtomicUsize::new(0));
        let finishes = Arc::new(AtomicUsize::new(0));
        let quarantines = Arc::new(AtomicUsize::new(0));
        let mut one_capacity = OneCapacityGuardFactory {
            active: Arc::clone(&active),
            begins: Arc::clone(&begins),
            finishes: Arc::clone(&finishes),
            quarantines: Arc::clone(&quarantines),
        };
        let cancellation = ExecutionCancellation::default();
        let primary = one_capacity
            .begin(resources(), cancellation.clone())
            .expect("admit the sole physical capacity slot");
        let mut owner = QemuHotForkWorldResourceOwner::new(primary, 1).expect("world owner");
        finish_primary_lifecycle(&mut owner, "primary");

        let broker = QemuHotForkWorldAuxiliaryResourceBroker::new();
        let binding = broker.bind(&owner).expect("bind retained aggregate");
        let mut replay_resources =
            QemuHotForkWorldAuxiliaryResourceFactory::new(broker, one_capacity);
        let requirements = QemuLaunchResourceRequirements::from_vm_shape(1, 1, false);

        let mut first = replay_resources
            .begin(resources(), cancellation.clone())
            .expect("first retained private replay");
        assert!(matches!(
            first,
            QemuHotForkWorldAuxiliaryResourceGuard::Retained(_)
        ));
        let first_path = first
            .prepare_generation_run_directory(requirements)
            .expect("first private run directory")
            .path()
            .to_path_buf();
        assert!(
            replay_resources
                .begin(resources(), cancellation.clone())
                .is_err()
        );
        first.finish().expect("finish first private replay");

        let mut second = replay_resources
            .begin(resources(), cancellation.clone())
            .expect("second retained private replay");
        let second_path = second
            .prepare_generation_run_directory(requirements)
            .expect("second private run directory")
            .path()
            .to_path_buf();
        assert_ne!(first_path, second_path);
        assert_eq!(begins.load(Ordering::Acquire), 1);
        assert_eq!(active.load(Ordering::Acquire), 1);
        second.finish().expect("finish second private replay");

        drop(binding);
        assert!(
            replay_resources
                .begin(resources(), cancellation.clone())
                .is_err()
        );
        owner.finish().expect("release retained aggregate");
        assert_eq!(active.load(Ordering::Acquire), 0);

        let mut independent = replay_resources
            .begin(resources(), cancellation)
            .expect("fresh fallback after aggregate release");
        assert!(matches!(
            independent,
            QemuHotForkWorldAuxiliaryResourceGuard::Fresh(_)
        ));
        let independent_path = independent
            .prepare_generation_run_directory(requirements)
            .expect("independent private run directory")
            .path()
            .to_path_buf();
        assert_ne!(first_path, independent_path);
        assert_ne!(second_path, independent_path);
        independent.finish().expect("finish fresh fallback");

        assert_eq!(begins.load(Ordering::Acquire), 2);
        assert_eq!(finishes.load(Ordering::Acquire), 2);
        assert_eq!(quarantines.load(Ordering::Acquire), 0);
    }

    #[test]
    fn auxiliary_cleanup_failure_quarantines_and_poisons_the_aggregate() {
        let finishes = Arc::new(AtomicUsize::new(0));
        let quarantines = Arc::new(AtomicUsize::new(0));
        let mut owner = QemuHotForkWorldResourceOwner::new(
            guard(Arc::clone(&finishes), Arc::clone(&quarantines)),
            1,
        )
        .expect("world owner");
        finish_primary_lifecycle(&mut owner, "node");
        let mut auxiliary = owner
            .auxiliary_lifecycle_guard()
            .expect("auxiliary lifecycle");

        auxiliary.quarantine();
        assert!(owner.auxiliary_lifecycle_guard().is_err());
        assert!(owner.finish().is_err());

        assert_eq!(finishes.load(Ordering::Acquire), 0);
        assert_eq!(quarantines.load(Ordering::Acquire), 1);
    }

    #[test]
    fn aggregate_finish_refuses_an_active_auxiliary_lifecycle() {
        let finishes = Arc::new(AtomicUsize::new(0));
        let quarantines = Arc::new(AtomicUsize::new(0));
        let mut owner = QemuHotForkWorldResourceOwner::new(
            guard(Arc::clone(&finishes), Arc::clone(&quarantines)),
            1,
        )
        .expect("world owner");
        finish_primary_lifecycle(&mut owner, "node");
        let auxiliary = owner
            .auxiliary_lifecycle_guard()
            .expect("auxiliary lifecycle");

        assert!(owner.finish().is_err());
        drop(auxiliary);

        assert_eq!(finishes.load(Ordering::Acquire), 0);
        assert_eq!(quarantines.load(Ordering::Acquire), 1);
    }
}
