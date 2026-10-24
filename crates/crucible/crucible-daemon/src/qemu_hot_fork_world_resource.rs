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
use std::sync::{Arc, Mutex, TryLockError, Weak};

// crucible-lint: allow host-nondeterminism-state -- exact node generations index operational resource ownership, not scheduler decisions or guest time.
use crate::ProductionVmNodeGeneration;
use crucible_campaign::AttemptResourceLimits;
use crucible_qemu_host::{
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

/// Distinguishes a member's actual return from retained terminal ownership.
///
/// This local receipt never attests aggregate resource closure. Quarantine and
/// unreaped-child transfer leave the aggregate's original cause untouched.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WorldMemberRetirement {
    Active,
    Returned,
    Quarantined,
}

impl WorldMemberRetirement {
    fn already_returned(self) -> Result<bool, QemuWorldMemberCleanupStatus> {
        match self {
            Self::Active => Ok(false),
            Self::Returned => Ok(true),
            Self::Quarantined => Err(QemuWorldMemberCleanupStatus::Retained {
                operation: "finish hot-fork World member",
            }),
        }
    }
}

/// Aggregate return is independent of whether a local message was allocated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WorldResourceRetirement {
    Active,
    Returned,
    Retained,
}

/// Reports local member-accounting status without an underlying host error.
///
/// Member release never calls the aggregate guard's cleanup. This finite type
/// cannot carry an arbitrary backend error or detached physical custody.
#[derive(Debug, thiserror::Error)]
pub enum QemuWorldMemberCleanupStatus {
    /// This member previously transferred its containing owner to quarantine.
    #[error("{operation} retains unresolved cleanup ownership")]
    Retained {
        /// Existing operation whose member remains retained.
        operation: &'static str,
    },
    /// The exact shared registry refused this member's release.
    #[error("manage aggregate hot-fork world resources executor operation failed: {message}")]
    Registry {
        /// Existing status diagnostic, with no backend owner inside it.
        message: String,
    },
}

impl QemuWorldMemberCleanupStatus {
    pub(super) fn registry(message: impl Into<String>) -> Self {
        Self::Registry {
            message: message.into(),
        }
    }

    pub(crate) fn into_realization(self) -> QemuVmRealizationError {
        match self {
            Self::Retained { operation } => QemuVmRealizationError::CleanupRetained { operation },
            Self::Registry { message } => world_resource_error(message),
        }
    }
}

struct QemuHotForkWorldResourceState<G>
where
    G: QemuAttemptResourceGuard,
{
    guard: G,
    source_world: Option<Arc<Mutex<crate::ProductionVmHotForkSourceWorld>>>,
    maximum_nodes: usize,
    issued: BTreeSet<ProductionVmNodeGeneration>,
    released: BTreeSet<ProductionVmNodeGeneration>,
    lifecycle_launcher_required: bool,
    lifecycle_launcher_finished: bool,
    auxiliary_lifecycle_active: bool,
    retirement: WorldResourceRetirement,
    terminal_failure: Option<String>,
}

impl<G> QemuHotForkWorldResourceState<G>
where
    G: QemuAttemptProcessResourceGuard,
{
    // All target generations use the same retained Source quota. Ordinary
    // source-free owners remain available for non-target component fixtures.
    fn prepare_generation_run_directory(
        &mut self,
        target_contract: &QemuChildProcessContract,
        requirements: QemuLaunchResourceRequirements,
    ) -> Result<QemuPreparedRunDirectory, QemuVmRealizationError> {
        #[cfg(target_os = "linux")]
        if let Some(source_world) = &self.source_world {
            let mut source = source_world.lock().map_err(|_| {
                world_resource_error("retained source-world ownership lock is poisoned")
            })?;
            return source
                .prepare_fork_target_run_directory(target_contract, requirements)
                .map_err(|error| world_resource_error(error.to_string()));
        }
        self.guard.prepare_generation_run_directory(requirements)
    }
}

/// Observes which retained participant still excludes aggregate release.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum QemuHotForkWorldReleaseReadiness {
    /// Every issued target and required lifecycle has finished its handoff.
    Ready,
    /// At least one exact issued child target has not finished.
    AwaitingTargets,
    /// The issued primary lifecycle launcher has not finished.
    AwaitingLifecycleLauncher,
    /// An auxiliary lifecycle still retains the aggregate contract.
    AwaitingAuxiliaryLifecycle,
}

/// Refuses an unobservable or terminal aggregate release observation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum QemuHotForkWorldReleaseReadinessError {
    /// Another participant currently holds the same registry.
    #[error("hot-fork world resource registry remains borrowed")]
    Borrowed,
    /// A prior registry operation panicked while holding its lock.
    #[error("hot-fork world resource registry is poisoned")]
    Poisoned,
    /// Aggregate release or quarantine has already made this owner terminal.
    #[error("hot-fork world resource owner is terminal")]
    Terminal,
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
                .field(
                    "terminal",
                    &(state.retirement != WorldResourceRetirement::Active),
                ),
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
                source_world: None,
                maximum_nodes,
                issued: BTreeSet::new(),
                released: BTreeSet::new(),
                lifecycle_launcher_required: false,
                lifecycle_launcher_finished: false,
                auxiliary_lifecycle_active: false,
                retirement: WorldResourceRetirement::Active,
                terminal_failure: None,
            })),
            resources,
            cancellation,
        })
    }

    /// Retains the complete source alongside the actual same-family target guard.
    ///
    /// # Errors
    /// Refuses an invalid world bound while retaining both physical authorities.
    pub(crate) fn new_fork_target(
        guard: G,
        maximum_nodes: usize,
        source_world: Arc<Mutex<crate::ProductionVmHotForkSourceWorld>>,
    ) -> Result<Self, QemuVmRealizationError> {
        let owner = match Self::new(guard, maximum_nodes) {
            Ok(owner) => owner,
            Err(error) => {
                std::mem::forget(source_world);
                return Err(error);
            }
        };
        let mut state = owner
            .state
            .lock()
            .map_err(|_| world_resource_error("new target world resource registry is poisoned"))?;
        state.source_world = Some(source_world);
        drop(state);
        Ok(owner)
    }

    /// Moves an actual Target guard using its already validated selected bound.
    ///
    /// The caller has retained the same selected storage since Source admission.
    /// This operation allocates only its prepaid shared body and cannot refuse
    /// after taking the guard; it performs no native or Source operation.
    pub(crate) fn from_prepared_target(
        guard: G,
        selected: &crate::qemu_lifecycle_launcher::TargetConstructionStorage,
        source_world: Arc<Mutex<crate::ProductionVmHotForkSourceWorld>>,
    ) -> Self {
        let resources = guard.resource_limits();
        let cancellation = guard.cancellation().clone();
        Self {
            state: Arc::new(Mutex::new(QemuHotForkWorldResourceState {
                guard,
                source_world: Some(source_world),
                maximum_nodes: selected.member_count(),
                issued: BTreeSet::new(),
                released: BTreeSet::new(),
                lifecycle_launcher_required: false,
                lifecycle_launcher_finished: false,
                auxiliary_lifecycle_active: false,
                retirement: WorldResourceRetirement::Active,
                terminal_failure: None,
            })),
            resources,
            cancellation,
        }
    }

    /// Aliases only this existing indivisible aggregate allocation.
    pub(crate) fn share(&self) -> Self {
        Self {
            state: Arc::clone(&self.state),
            resources: self.resources,
            cancellation: self.cancellation.clone(),
        }
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
        if state.retirement != WorldResourceRetirement::Active {
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
            #[cfg(test)]
            component_ram_facts: false,
            host_ram: None,
            state: Arc::clone(&self.state),
            identity,
            resources: self.resources,
            cancellation: self.cancellation.clone(),
            retirement: WorldMemberRetirement::Active,
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
        if state.retirement != WorldResourceRetirement::Active {
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
            retirement: WorldMemberRetirement::Active,
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

    /// Observes existing release latches without finishing or quarantining them.
    ///
    /// Pending participants may still complete through their retained owners.
    /// A ready observation grants no resource authority: the caller must retain
    /// its existing retirement operation and still execute actual `finish`.
    ///
    /// # Errors
    /// Refuses a borrowed, poisoned or terminal registry without waiting,
    /// invoking its guard or constructing a replacement diagnostic allocation.
    pub(crate) fn release_readiness(
        &self,
    ) -> Result<QemuHotForkWorldReleaseReadiness, QemuHotForkWorldReleaseReadinessError> {
        let state = self.state.try_lock().map_err(|error| match error {
            TryLockError::WouldBlock => QemuHotForkWorldReleaseReadinessError::Borrowed,
            TryLockError::Poisoned(_) => QemuHotForkWorldReleaseReadinessError::Poisoned,
        })?;
        if state.retirement != WorldResourceRetirement::Active {
            return Err(QemuHotForkWorldReleaseReadinessError::Terminal);
        }
        if state.issued != state.released {
            return Ok(QemuHotForkWorldReleaseReadiness::AwaitingTargets);
        }
        if state.lifecycle_launcher_required && !state.lifecycle_launcher_finished {
            return Ok(QemuHotForkWorldReleaseReadiness::AwaitingLifecycleLauncher);
        }
        if state.auxiliary_lifecycle_active {
            return Ok(QemuHotForkWorldReleaseReadiness::AwaitingAuxiliaryLifecycle);
        }
        Ok(QemuHotForkWorldReleaseReadiness::Ready)
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
    pub fn finish(&mut self) -> Result<(), crate::QemuAttemptResourceGuardCleanupFailure> {
        let mut state = self.state.lock().map_err(|_| {
            QemuWorldMemberCleanupStatus::registry("hot-fork world resource registry is poisoned")
        })?;
        match state.retirement {
            WorldResourceRetirement::Active => {}
            WorldResourceRetirement::Returned => return Ok(()),
            WorldResourceRetirement::Retained => {
                return Err(
                    crate::QemuAttemptResourceGuardCleanupFailure::retained_status(
                        "repeat retained hot-fork World retirement",
                    ),
                );
            }
        }
        if state.issued != state.released {
            let message =
                String::from("hot-fork world aggregate release has an unfinished child target");
            state.guard.quarantine();
            state.retirement = WorldResourceRetirement::Retained;
            state.terminal_failure = Some(message.clone());
            return Err(
                crate::QemuAttemptResourceGuardCleanupFailure::member_status(
                    QemuWorldMemberCleanupStatus::registry(message),
                )
                .after_quarantine(),
            );
        }
        if state.lifecycle_launcher_required && !state.lifecycle_launcher_finished {
            let message = String::from(
                "hot-fork world aggregate release preceded lifecycle launcher cleanup",
            );
            state.guard.quarantine();
            state.retirement = WorldResourceRetirement::Retained;
            state.terminal_failure = Some(message.clone());
            return Err(
                crate::QemuAttemptResourceGuardCleanupFailure::member_status(
                    QemuWorldMemberCleanupStatus::registry(message),
                )
                .after_quarantine(),
            );
        }
        if state.auxiliary_lifecycle_active {
            let message =
                String::from("hot-fork world aggregate release has an active auxiliary lifecycle");
            state.guard.quarantine();
            state.retirement = WorldResourceRetirement::Retained;
            state.terminal_failure = Some(message.clone());
            return Err(
                crate::QemuAttemptResourceGuardCleanupFailure::member_status(
                    QemuWorldMemberCleanupStatus::registry(message),
                )
                .after_quarantine(),
            );
        }
        let result = state.guard.finish();
        state.retirement = if result.is_ok() {
            WorldResourceRetirement::Returned
        } else {
            WorldResourceRetirement::Retained
        };
        result
    }

    /// Returns existing vector capacity after every real Target receipt closes.
    ///
    /// A unique registry is only safe access to G. The underlying storage checks
    /// its own genuine loan journals before clearing returned host metadata.
    /// Only then can this containing facade retire its remaining aliases.
    pub(crate) fn recover_target_construction_storage(
        &mut self,
        storage: &mut crate::TargetConstructionStorage,
    ) -> bool {
        let Some(state) = Arc::get_mut(&mut self.state) else {
            return false;
        };
        let Ok(state) = state.get_mut() else {
            return false;
        };
        if state.issued != state.released
            || (state.lifecycle_launcher_required && !state.lifecycle_launcher_finished)
            || state.auxiliary_lifecycle_active
            || !state.guard.recover_target_construction_storage(storage)
        {
            return false;
        }
        state.retirement = WorldResourceRetirement::Returned;
        true
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
    retirement: WorldMemberRetirement,
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
        if self.retirement != WorldMemberRetirement::Active
            || state.retirement != WorldResourceRetirement::Active
        {
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
        if self.retirement != WorldMemberRetirement::Active
            || state.retirement != WorldResourceRetirement::Active
        {
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
    fn finish(&mut self) -> Result<(), crate::QemuAttemptResourceGuardCleanupFailure> {
        if self.retirement.already_returned().map_err(|status| {
            crate::QemuAttemptResourceGuardCleanupFailure::member_status(status).after_quarantine()
        })? {
            return Ok(());
        }
        let mut state = self.state.lock().map_err(|_| {
            QemuWorldMemberCleanupStatus::registry("hot-fork world resource registry is poisoned")
        })?;
        if state.retirement != WorldResourceRetirement::Active {
            return Err((QemuWorldMemberCleanupStatus::registry(
                state
                    .terminal_failure
                    .as_deref()
                    .unwrap_or("hot-fork world resource owner is terminal"),
            ))
            .into());
        }
        state.lifecycle_launcher_finished = true;
        self.retirement = WorldMemberRetirement::Returned;
        Ok(())
    }

    fn quarantine(&mut self) {
        if self.retirement == WorldMemberRetirement::Active {
            quarantine_world_state(&self.state);
            self.retirement = WorldMemberRetirement::Quarantined;
        }
    }
}

impl<G> QemuAttemptProcessResourceGuard for QemuHotForkWorldLifecycleGuard<G>
where
    G: QemuAttemptProcessResourceGuard,
{
    #[cfg(target_os = "linux")]
    fn bind_fork_target_ram_custody(
        &mut self,
        contract: &QemuChildProcessContract,
        registration: &crucible_qemu_host::ram_control::RamControlRegistration,
        supervisor: &crucible_host_resources::host_supervision::HostOperationSupervisor,
        guest_ram_bytes: u64,
        custody: &crucible_qemu_host::QemuRamLaunchCustody,
    ) -> Result<(), QemuVmRealizationError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| world_resource_error("hot-fork world resource registry is poisoned"))?;
        if self.retirement != WorldMemberRetirement::Active
            || state.retirement != WorldResourceRetirement::Active
        {
            return Err(world_resource_error(
                "target RAM keeper launcher is terminal",
            ));
        }
        state.guard.bind_fork_target_ram_custody(
            contract,
            registration,
            supervisor,
            guest_ram_bytes,
            custody,
        )
    }

    #[cfg(target_os = "linux")]
    fn fork_target_is_owned(&self) -> bool {
        self.state
            .lock()
            .map_or(true, |state| state.guard.fork_target_is_owned())
    }

    #[cfg(target_os = "linux")]
    fn prepare_fork_target(
        &mut self,
    ) -> Result<crucible_qemu_host::QemuForkTargetPreparation, QemuVmRealizationError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| world_resource_error("hot-fork world resource registry is poisoned"))?;
        if self.retirement != WorldMemberRetirement::Active
            || state.retirement != WorldResourceRetirement::Active
        {
            return Err(world_resource_error("target source launcher is terminal"));
        }
        state.guard.prepare_fork_target()
    }

    #[cfg(target_os = "linux")]
    fn prepare_fork_target_run_directory(
        &mut self,
        target_contract: &QemuChildProcessContract,
        requirements: QemuLaunchResourceRequirements,
    ) -> Result<QemuPreparedRunDirectory, QemuVmRealizationError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| world_resource_error("hot-fork world resource registry is poisoned"))?;
        if self.retirement != WorldMemberRetirement::Active
            || state.retirement != WorldResourceRetirement::Active
        {
            return Err(world_resource_error("target source launcher is terminal"));
        }
        state
            .guard
            .prepare_fork_target_run_directory(target_contract, requirements)
    }

    fn installed_node_issuer(
        &self,
    ) -> Result<crucible_qemu_host::InstalledNodeLaunchIssuer, crucible_qemu_host::QemuLiveNodeStepGateError>
    {
        let state = self.state.lock().map_err(|_| {
            crucible_qemu_host::QemuLiveNodeStepGateError::OriginalNativeAccount {
                source: crucible_qemu_host::OriginalActorAccountError::Unavailable,
            }
        })?;
        if self.retirement != WorldMemberRetirement::Active
            || state.retirement != WorldResourceRetirement::Active
        {
            return Err(
                crucible_qemu_host::QemuLiveNodeStepGateError::OriginalNativeAccount {
                    source: crucible_qemu_host::OriginalActorAccountError::Unavailable,
                },
            );
        }
        state.guard.installed_node_issuer()
    }

    fn launch_fresh_node(
        &self,
        config: &crucible_qemu_host::QemuLiveNodeStepGateConfig,
        admission: crucible_qemu_host::QemuProductionFreshLaunchAdmission<'_>,
    ) -> Result<crucible_qemu_host::QemuNode, crucible_qemu_host::QemuLiveNodeStepGateError> {
        self.installed_node_issuer()?
            .launch_fresh_node(config, admission)
    }

    fn launch_exact_node(
        &self,
        request: crucible_qemu_host::QemuProductionExactRestoreRequest,
    ) -> Result<
        crucible_qemu_host::QemuProductionExactRestoreLaunch,
        crucible_qemu_host::QemuLiveNodeStepGateError,
    > {
        self.installed_node_issuer()?.launch_exact_node(request)
    }

    fn native_resource_controller(
        &mut self,
    ) -> Result<Option<crucible_qemu_host::LinuxQemuNativeResourceController>, QemuVmRealizationError>
    {
        let mut state = self
            .state
            .lock()
            .map_err(|_| world_resource_error("hot-fork world resource registry is poisoned"))?;
        if self.retirement != WorldMemberRetirement::Active
            || state.retirement != WorldResourceRetirement::Active
        {
            return Err(world_resource_error(
                "native resource controller owner is not operational",
            ));
        }
        state.guard.native_resource_controller()
    }

    fn child_process_contract(&self) -> Result<&QemuChildProcessContract, QemuVmRealizationError> {
        let state = self
            .state
            .lock()
            .map_err(|_| world_resource_error("hot-fork world resource registry is poisoned"))?;
        if self.retirement != WorldMemberRetirement::Active
            || state.retirement != WorldResourceRetirement::Active
        {
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
        if self.retirement != WorldMemberRetirement::Active
            || state.retirement != WorldResourceRetirement::Active
        {
            return Err(world_resource_error(
                "hot-fork world lifecycle launcher cannot prepare a generation directory",
            ));
        }
        state.prepare_generation_run_directory(&self.process_contract, requirements)
    }

    fn retain_failed_launch_child(&mut self, child: QemuNodeChild) {
        match self.state.lock() {
            Ok(mut state) => {
                state.guard.retain_failed_launch_child(child);
                state.guard.quarantine();
                state.retirement = WorldResourceRetirement::Retained;
                state.terminal_failure.get_or_insert_with(|| {
                    String::from("hot-fork world lifecycle retained an unreaped launch child")
                });
            }
            Err(poisoned) => {
                let mut state = poisoned.into_inner();
                state.guard.retain_failed_launch_child(child);
                state.guard.quarantine();
                state.retirement = WorldResourceRetirement::Retained;
                state.terminal_failure.get_or_insert_with(|| {
                    String::from("hot-fork world lifecycle resource registry was poisoned")
                });
            }
        }
        self.retirement = WorldMemberRetirement::Quarantined;
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
            if state.retirement == WorldResourceRetirement::Active {
                state.guard.quarantine();
                state.retirement = WorldResourceRetirement::Retained;
                state.terminal_failure = Some(String::from(
                    "hot-fork world resources were transferred to quarantine",
                ));
            }
        }
        Err(poisoned) => {
            let mut state = poisoned.into_inner();
            if state.retirement == WorldResourceRetirement::Active {
                state.guard.quarantine();
                state.retirement = WorldResourceRetirement::Retained;
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
