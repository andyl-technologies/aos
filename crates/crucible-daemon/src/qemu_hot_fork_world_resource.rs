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

mod auxiliary;
mod node_target;

#[cfg(test)]
pub(crate) use auxiliary::QemuHotForkWorldAuxiliaryResourceGuard;
use auxiliary::QemuHotForkWorldAuxiliaryResourceHandle;
pub(crate) use auxiliary::{
    QemuHotForkWorldAuxiliaryResourceBinding, QemuHotForkWorldAuxiliaryResourceBroker,
    QemuHotForkWorldAuxiliaryResourceFactory,
};
pub(crate) use node_target::QemuHotForkWorldNodeTarget;

#[cfg(feature = "destructive-recovery-faults")]
const DESTRUCTIVE_RECOVERY_TRIGGER_ENVIRONMENT: &str = "CRUCIBLE_DESTRUCTIVE_RECOVERY_TRIGGER";
#[cfg(feature = "destructive-recovery-faults")]
const WORLD_FORK_PREFLIGHT_FAILURE_TRIGGER: &str =
    "crucible.destructive-recovery.world-fork-preflight-failure";

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
pub(crate) struct QemuHotForkWorldResourceOwner<G>
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
        if !state.issued.is_empty() && world_fork_preflight_failure_requested() {
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
            process_contract: None,
        })
    }

    /// Reserves one child generation with a duplicated concurrent launch contract.
    pub(crate) fn reserve_process_node(
        &mut self,
        identity: ProductionVmNodeGeneration,
    ) -> Result<QemuHotForkWorldNodeTarget<G>, QemuVmRealizationError>
    where
        G: QemuAttemptProcessResourceGuard,
    {
        let process_contract = {
            let state = self.state.lock().map_err(|_| {
                world_resource_error("hot-fork world resource registry is poisoned")
            })?;
            state
                .guard
                .child_process_contract()?
                .try_clone_for_attempt_generation()
                .map_err(|source| {
                    world_resource_error(format!(
                        "duplicate concurrent hot-fork node process contract: {source}"
                    ))
                })?
        };
        let mut target = self.reserve_node(identity)?;
        target.process_contract = Some(process_contract);
        Ok(target)
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

impl<G> Drop for QemuHotForkWorldResourceOwner<G>
where
    G: QemuAttemptResourceGuard,
{
    fn drop(&mut self) {
        quarantine_world_state(&self.state);
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
fn world_fork_preflight_failure_requested() -> bool {
    std::env::var_os(DESTRUCTIVE_RECOVERY_TRIGGER_ENVIRONMENT).as_deref()
        == Some(std::ffi::OsStr::new(WORLD_FORK_PREFLIGHT_FAILURE_TRIGGER))
}

#[cfg(test)]
mod tests;
