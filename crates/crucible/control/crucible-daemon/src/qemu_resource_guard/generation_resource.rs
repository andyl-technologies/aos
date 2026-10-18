//! Process resource ownership for one QEMU execution generation.

use super::*;

mod storage;

use storage::GenerationNodeState;
pub use storage::QemuAttemptGenerationStorage;
pub(crate) use storage::QemuGenerationStorageSelection;

/// Typed refusal lending the same attempt's process contract to its stage.
#[cfg(any(test, all(target_os = "linux", feature = "private-measurement-domain")))]
#[derive(Debug, thiserror::Error)]
pub(crate) enum ProcessStageContractRefusal {
    #[error("configured process stage belongs to another or retired attempt")]
    NotCurrent,
    #[error(transparent)]
    Owner(QemuVmRealizationError),
}

#[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
impl ProcessStageContractRefusal {
    pub(crate) fn failure(&self) -> crate::ProductionVmParentParkStageOwnerCause<'_> {
        use crate::ProductionVmParentParkStageOwnerCause as Cause;
        match self {
            Self::NotCurrent => Cause::NotCurrent,
            Self::Owner(first) => Cause::Owner(first),
        }
    }
}

/// Attempt-wide guard owner with exact linear process-generation leases.
///
/// The owner seals one resource guard behind a bounded generation registry.
/// Only preselected scheduler nodes may advance to newer positive generations.
/// The live set retains at most the active generation and one staged successor,
/// matching the lifecycle's replace-before-reap transaction without permitting
/// an unbounded generation chain. Finished leases leave only one latest-
/// generation integer per scenario node. Dropping an unfinished lease poisons
/// aggregate release; dropping this owner transfers the underlying guard to
/// quarantine.
#[must_use = "finish the generation owner or transfer its guard to quarantine"]
pub struct QemuAttemptGenerationResourceOwner<G>
where
    G: QemuAttemptResourceGuard,
{
    guard: G,
    generations: Arc<Mutex<QemuAttemptGenerationState>>,
    retirement: GenerationResourceRetirement,
    terminal_failure: Option<String>,
}

/// Physical disposition is independent of optional diagnostic presentation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GenerationResourceRetirement {
    Active,
    Returned,
    Quarantined,
}

impl<G> fmt::Debug for QemuAttemptGenerationResourceOwner<G>
where
    G: QemuAttemptResourceGuard + fmt::Debug,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QemuAttemptGenerationResourceOwner")
            .field("guard", &self.guard)
            .field("retirement", &self.retirement)
            .field("terminal_failure", &self.terminal_failure)
            .finish_non_exhaustive()
    }
}

impl<G> QemuAttemptGenerationResourceOwner<G>
where
    G: QemuAttemptResourceGuard,
{
    pub(crate) fn matches_storage_selection(
        &self,
        selection: &QemuGenerationStorageSelection,
    ) -> bool {
        selection.matches(&self.generations)
    }

    pub(crate) fn with_guard_mut<T>(&mut self, apply: impl FnOnce(&mut G) -> T) -> T {
        apply(&mut self.guard)
    }

    /// Moves a guard into its already validated and allocated selected storage.
    ///
    /// No validation or allocation follows the guard move. Failure to prepare
    /// storage must be handled while the caller still owns the original guard.
    pub fn new(guard: G, storage: QemuAttemptGenerationStorage) -> Self {
        Self {
            guard,
            generations: storage.generations,
            retirement: GenerationResourceRetirement::Active,
            terminal_failure: None,
        }
    }

    /// Registers one strictly newer node generation and returns its linear lease.
    ///
    /// Registration is failure-atomic and never allocates registry storage.
    /// The node must belong to the preselected set and advance beyond its last
    /// issued generation. The lease must be finished only after its
    /// exact QEMU child has been reaped.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError::LoopFactory`] after terminal cleanup,
    /// registry poison, prior lease abandonment, node-bound exhaustion, or a
    /// duplicate/stale generation.
    pub fn register_generation(
        &mut self,
        identity: ProductionVmNodeGeneration,
    ) -> Result<QemuAttemptGenerationLease, LifecycleApiError> {
        if self.retirement != GenerationResourceRetirement::Active {
            return Err(generation_error(
                "QEMU attempt generation owner is already terminal",
            ));
        }
        let mut state = self
            .generations
            .lock()
            .map_err(|_| generation_error("QEMU attempt generation registry is poisoned"))?;
        if state.abandoned {
            return Err(generation_error(
                "a QEMU attempt generation lease was abandoned",
            ));
        }
        let index = state
            .nodes
            .binary_search_by(|row| row.node.cmp(identity.node()))
            .map_err(|_| {
                generation_error(format!(
                    "QEMU node `{}` was not selected before Source construction",
                    identity.node().name,
                ))
            })?;
        let row = &mut state.nodes[index];
        let free = row.active.iter().position(Option::is_none).ok_or_else(|| {
            generation_error(format!(
                "QEMU node `{}` already retains the active and staged generation leases",
                row.node.name,
            ))
        })?;
        if row
            .latest
            .is_some_and(|latest| identity.generation() <= latest)
        {
            return Err(generation_error(format!(
                "QEMU node `{}` generation {} does not advance beyond {:?}",
                row.node.name,
                identity.generation(),
                row.latest,
            )));
        }
        let previous_generation = row.latest;
        row.active[free] = Some(identity.generation());
        row.latest = Some(identity.generation());
        drop(state);
        Ok(QemuAttemptGenerationLease {
            identity,
            generations: Arc::clone(&self.generations),
            previous_generation,
            finished: false,
        })
    }

    /// Finishes the aggregate guard after every exact generation lease released.
    ///
    /// An abandoned or still-active lease causes immediate quarantine; aggregate
    /// CPU, memory, disk, and quantum ownership is never released from that
    /// state. The operation is idempotent after a successful finish.
    ///
    /// # Errors
    ///
    /// Retains a local API status when a lease remains active or abandoned, or
    /// the registry is poisoned. Underlying guard cleanup moves its actual leaf
    /// to the enclosing typed history. Later quarantine observations preserve
    /// the existing presentation without repeating cleanup or attesting return.
    pub fn finish(&mut self) -> Result<(), crate::ProductionVmConstructionCleanupError> {
        match self.retirement {
            GenerationResourceRetirement::Active => {}
            GenerationResourceRetirement::Returned => return Ok(()),
            GenerationResourceRetirement::Quarantined => {
                return Err((self
                    .terminal_failure
                    .as_ref()
                    .map_or(LifecycleApiError::CleanupRetained, |message| {
                        generation_error(message.clone())
                    }))
                .into());
            }
        }
        let release_allowed = self
            .generations
            .lock()
            .map(|state| {
                !state.abandoned
                    && state
                        .nodes
                        .iter()
                        .all(|row| row.active.iter().all(Option::is_none))
            })
            .map_err(|_| generation_error("QEMU attempt generation registry is poisoned"));
        match release_allowed {
            Ok(true) => {}
            Ok(false) => {
                let message = String::from(
                    "QEMU attempt aggregate release has an active or abandoned generation",
                );
                self.guard.quarantine();
                self.retirement = GenerationResourceRetirement::Quarantined;
                self.terminal_failure = Some(message.clone());
                return Err((generation_error(message)).into());
            }
            Err(error) => {
                let message = error.to_string();
                self.guard.quarantine();
                self.retirement = GenerationResourceRetirement::Quarantined;
                self.terminal_failure = Some(message);
                return Err((error).into());
            }
        }
        let result = self.guard.finish();
        // Latch containment before formatting a failure can unwind. Only the
        // successful result below can attest aggregate return.
        self.retirement = GenerationResourceRetirement::Quarantined;
        match result {
            Ok(()) => {
                self.retirement = GenerationResourceRetirement::Returned;
                Ok(())
            }
            // The actual leaf moves before any presentation. Subsequent
            // terminal observations use the existing allocation-free status;
            // the enclosing cleanup history retains this first cause.
            Err(error) => Err(error.into()),
        }
    }

    /// Transfers the aggregate guard to quarantine without releasing resources.
    pub fn quarantine(&mut self) {
        if self.retirement != GenerationResourceRetirement::Active {
            return;
        }
        self.guard.quarantine();
        self.retirement = GenerationResourceRetirement::Quarantined;
        self.terminal_failure = Some(String::from(
            "QEMU attempt aggregate resources were transferred to quarantine",
        ));
    }

    /// Retains terminal original launch custody without allocating a diagnostic.
    pub(crate) fn quarantine_original_launch(&mut self) {
        if self.retirement != GenerationResourceRetirement::Active {
            return;
        }
        self.guard.quarantine();
        self.retirement = GenerationResourceRetirement::Quarantined;
        // The enclosing typed error retains the actual cause. Its absence here
        // must neither allocate a replacement nor attest physical return.
        self.terminal_failure = None;
    }

    /// Checks cancellation and hard-resource state between bounded operations.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError::AttemptOperational`] after terminal cleanup,
    /// cancellation, resource exhaustion, or enforcement-state failure.
    pub fn check_operational_boundary(&mut self) -> Result<(), LifecycleApiError> {
        if self.retirement != GenerationResourceRetirement::Active {
            return Err(terminal_attempt_operational_error(
                "QEMU attempt generation owner is already terminal",
            ));
        }
        self.guard.check_operational_boundary().map_err(|error| {
            attempt_operational_error("check QEMU attempt operational boundary", error)
        })
    }
}

impl<G> QemuAttemptGenerationResourceOwner<G>
where
    G: QemuAttemptProcessResourceGuard,
{
    /// Borrows this generation's exact node contract under the same guard.
    #[cfg(any(test, all(target_os = "linux", feature = "private-measurement-domain")))]
    pub(crate) fn with_process_stage_contract_for_node<T>(
        &mut self,
        node: &NodeId,
        cancellation: &ExecutionCancellation,
        invoke: impl FnOnce(&QemuChildProcessContract) -> T,
    ) -> Result<T, ProcessStageContractRefusal> {
        if self.retirement != GenerationResourceRetirement::Active
            || !self.guard.cancellation().same_incarnation(cancellation)
        {
            return Err(ProcessStageContractRefusal::NotCurrent);
        }
        self.guard
            .check_operational_boundary()
            .map_err(ProcessStageContractRefusal::Owner)?;
        let contract = self
            .guard
            .child_process_contract_for_node(node)
            .map_err(ProcessStageContractRefusal::Owner)?;
        Ok(invoke(contract))
    }

    /// Lends an exact member contract without selecting another physical node.
    ///
    /// # Errors
    /// Refuses terminal custody, an unknown node or changed native ownership.
    pub(crate) fn child_process_contract_for_node(
        &self,
        node: &NodeId,
    ) -> Result<&QemuChildProcessContract, LifecycleApiError> {
        if self.retirement != GenerationResourceRetirement::Active {
            return Err(generation_error("QEMU generation owner is terminal"));
        }
        self.guard
            .child_process_contract_for_node(node)
            .map_err(|error| attempt_operational_error("lend exact node contract", error))
    }

    /// Prepares this node's fresh directory in its actual retained quota.
    pub(crate) fn prepare_generation_run_directory_for_node(
        &mut self,
        node: &NodeId,
        requirements: QemuLaunchResourceRequirements,
    ) -> Result<QemuPreparedRunDirectory, LifecycleApiError> {
        self.check_operational_boundary()?;
        self.guard
            .prepare_generation_run_directory_for_node(node, requirements)
            .map_err(|error| attempt_operational_error("prepare exact node directory", error))
    }

    /// Borrows the actual issuer attached to this selected node's family.
    pub(crate) fn installed_node_issuer_for_node(
        &self,
        node: &NodeId,
    ) -> Result<crucible_qemu_host::InstalledNodeLaunchIssuer, crucible_qemu_host::QemuLiveNodeStepGateError>
    {
        if self.retirement != GenerationResourceRetirement::Active {
            return Err(
                crucible_qemu_host::QemuLiveNodeStepGateError::OriginalNativeAccount {
                    source: crucible_qemu_host::OriginalActorAccountError::Unavailable,
                },
            );
        }
        self.guard.installed_node_issuer_for_node(node)
    }

    /// Launches under this node's retained physical owner without new credit.
    pub(crate) fn launch_fresh_node_for_node(
        &self,
        node: &NodeId,
        config: &crucible_qemu_host::QemuLiveNodeStepGateConfig,
        admission: crucible_qemu_host::QemuProductionFreshLaunchAdmission<'_>,
    ) -> Result<crucible_qemu_host::QemuNode, crucible_qemu_host::QemuLiveNodeStepGateError> {
        if self.retirement != GenerationResourceRetirement::Active {
            return Err(
                crucible_qemu_host::QemuLiveNodeStepGateError::OriginalNativeAccount {
                    source: crucible_qemu_host::OriginalActorAccountError::Unavailable,
                },
            );
        }
        self.guard
            .launch_fresh_node_for_node(node, config, admission)
    }

    /// Restores through this selected node's existing physical issuer.
    pub(crate) fn launch_exact_node_for_node(
        &self,
        node: &NodeId,
        request: crucible_qemu_host::QemuProductionExactRestoreRequest,
    ) -> Result<
        crucible_qemu_host::QemuProductionExactRestoreLaunch,
        crucible_qemu_host::QemuLiveNodeStepGateError,
    > {
        if self.retirement != GenerationResourceRetirement::Active {
            return Err(
                crucible_qemu_host::QemuLiveNodeStepGateError::OriginalNativeAccount {
                    source: crucible_qemu_host::OriginalActorAccountError::Unavailable,
                },
            );
        }
        self.guard.launch_exact_node_for_node(node, request)
    }

    /// Keeps an unreaped child with the same selected physical member.
    pub(crate) fn retain_failed_launch_child_for_node(
        &mut self,
        node: &NodeId,
        child: QemuNodeChild,
    ) {
        self.guard.retain_failed_launch_child_for_node(node, child);
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn fork_target_is_owned_for_node(&self, node: &NodeId) -> bool {
        self.guard.fork_target_is_owned_for_node(node)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn native_world_identity(
        &self,
    ) -> Result<
        crucible_host_resources::host_services::process_birth::NativeWorldIdentity,
        QemuVmRealizationError,
    > {
        self.guard.native_world_identity()
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn prepare_fork_target_for_node(
        &mut self,
        node: &NodeId,
    ) -> Result<
        crucible_qemu_host::QemuForkTargetPreparation,
        crate::qemu_lifecycle_launcher::TargetPreparationFailure,
    > {
        self.check_operational_boundary()?;
        self.guard
            .prepare_fork_target_for_node(node)
            .map_err(crate::qemu_lifecycle_launcher::TargetPreparationFailure::Native)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn prepare_fork_target_run_directory_for_node(
        &mut self,
        node: &NodeId,
        contract: &QemuChildProcessContract,
        requirements: QemuLaunchResourceRequirements,
    ) -> Result<QemuPreparedRunDirectory, LifecycleApiError> {
        self.check_operational_boundary()?;
        self.guard
            .prepare_fork_target_run_directory_for_node(node, contract, requirements)
            .map_err(|error| {
                attempt_operational_error("prepare exact node Target directory", error)
            })
    }

    // This fixed callback borrows the actual owner's process contract only.
    // It cannot select an event, descriptor, or independently supplied guard.
    #[cfg(any(test, all(target_os = "linux", feature = "private-measurement-domain")))]
    pub(crate) fn with_process_stage_contract<T>(
        &mut self,
        cancellation: &ExecutionCancellation,
        invoke: impl FnOnce(&QemuChildProcessContract) -> T,
    ) -> Result<T, ProcessStageContractRefusal> {
        if self.retirement != GenerationResourceRetirement::Active
            || !self.guard.cancellation().same_incarnation(cancellation)
        {
            return Err(ProcessStageContractRefusal::NotCurrent);
        }
        self.guard
            .check_operational_boundary()
            .map_err(ProcessStageContractRefusal::Owner)?;
        let contract = self
            .guard
            .child_process_contract()
            .map_err(ProcessStageContractRefusal::Owner)?;
        Ok(invoke(contract))
    }

    /// Reports the actual guard's retained target loan before source cleanup.
    #[cfg(target_os = "linux")]
    pub(crate) fn fork_target_is_owned(&self) -> bool {
        self.guard.fork_target_is_owned()
    }

    /// Lends the source permit without replacing this generation's actual guard.
    ///
    /// # Errors
    /// Refuses terminal ownership, operational failure or missing source custody.
    #[cfg(target_os = "linux")]
    pub(crate) fn prepare_fork_target(
        &mut self,
    ) -> Result<
        crucible_qemu_host::QemuForkTargetPreparation,
        crate::qemu_lifecycle_launcher::TargetPreparationFailure,
    > {
        self.check_operational_boundary()?;
        self.guard
            .prepare_fork_target()
            .map_err(crate::qemu_lifecycle_launcher::TargetPreparationFailure::Native)
    }

    /// Prepares the target's distinct generation under the actual source quota.
    ///
    /// # Errors
    /// Refuses terminal ownership, a foreign target or unavailable source storage.
    /// Prepares RAM through the exact saved Target before a second birth.
    ///
    /// # Errors
    /// Refuses terminal ownership or an unavailable matching Target role.
    #[cfg(target_os = "linux")]
    pub(crate) fn with_fork_target_ram_admission_for_node(
        &self,
        node: &NodeId,
        contract: &QemuChildProcessContract,
        prepare: &mut dyn FnMut(
            &crucible_qemu_host::QemuForkTargetRamAdmission<'_>,
        ) -> Result<
            crucible_qemu_host::ram_control::RamControlRegistration,
            QemuVmRealizationError,
        >,
    ) -> Result<crucible_qemu_host::ram_control::RamControlRegistration, QemuVmRealizationError> {
        if self.retirement != GenerationResourceRetirement::Active {
            return Err(QemuVmRealizationError::ExecutorUnavailable {
                operation: "borrow selected Target RAM admission",
                message: String::from("generation owner is terminal"),
            });
        }
        self.guard
            .with_fork_target_ram_admission_for_node(node, contract, prepare)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn prepare_fork_target_run_directory(
        &mut self,
        target_contract: &QemuChildProcessContract,
        requirements: QemuLaunchResourceRequirements,
    ) -> Result<QemuPreparedRunDirectory, LifecycleApiError> {
        self.check_operational_boundary()?;
        self.guard
            .prepare_fork_target_run_directory(target_contract, requirements)
            .map_err(|error| {
                generation_error(format!("prepare same-family target directory: {error}"))
            })
    }

    /// Provisions one fresh generation directory under the aggregate guard.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError::LoopFactory`] after aggregate cleanup or
    /// when the guard rejects launch admission or storage provisioning.
    pub fn prepare_generation_run_directory(
        &mut self,
        requirements: QemuLaunchResourceRequirements,
    ) -> Result<QemuPreparedRunDirectory, LifecycleApiError> {
        if self.retirement != GenerationResourceRetirement::Active {
            return Err(generation_error(
                "QEMU attempt generation owner is already terminal",
            ));
        }
        self.guard
            .prepare_generation_run_directory(requirements)
            .map_err(|error| {
                generation_error(format!("prepare QEMU generation directory: {error}"))
            })
    }

    /// Returns the sealed attempt process contract for guarded generation spawn.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError::LoopFactory`] after aggregate cleanup or
    /// when the guard cannot authenticate the retained process contract.
    pub fn child_process_contract(&self) -> Result<&QemuChildProcessContract, LifecycleApiError> {
        if self.retirement != GenerationResourceRetirement::Active {
            return Err(generation_error(
                "QEMU attempt generation owner is already terminal",
            ));
        }
        self.guard.child_process_contract().map_err(|error| {
            generation_error(format!("lend QEMU generation process contract: {error}"))
        })
    }

    /// Launches under this owner's retained guard without replacing its custody.
    pub(crate) fn launch_fresh_node(
        &self,
        config: &crucible_qemu_host::QemuLiveNodeStepGateConfig,
        admission: crucible_qemu_host::QemuProductionFreshLaunchAdmission<'_>,
    ) -> Result<crucible_qemu_host::QemuNode, crucible_qemu_host::QemuLiveNodeStepGateError> {
        if self.retirement != GenerationResourceRetirement::Active {
            return Err(
                crucible_qemu_host::QemuLiveNodeStepGateError::OriginalNativeAccount {
                    source: crucible_qemu_host::OriginalActorAccountError::Unavailable,
                },
            );
        }
        self.guard.launch_fresh_node(config, admission)
    }

    /// Restores through this same generation owner's retained physical guard.
    ///
    /// # Errors
    /// Refuses terminal ownership or the actual installed issuer and restore.
    pub(crate) fn launch_exact_node(
        &self,
        request: crucible_qemu_host::QemuProductionExactRestoreRequest,
    ) -> Result<
        crucible_qemu_host::QemuProductionExactRestoreLaunch,
        crucible_qemu_host::QemuLiveNodeStepGateError,
    > {
        if self.retirement != GenerationResourceRetirement::Active {
            return Err(
                crucible_qemu_host::QemuLiveNodeStepGateError::OriginalNativeAccount {
                    source: crucible_qemu_host::OriginalActorAccountError::Unavailable,
                },
            );
        }
        self.guard.launch_exact_node(request)
    }

    /// Retains an unreaped child from a failed generation launch.
    pub fn retain_failed_launch_child(&mut self, child: QemuNodeChild) {
        self.guard.retain_failed_launch_child(child);
    }

    /// Charges one scheduler quantum before generation guest progress.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError::AttemptOperational`] on cancellation, terminal
    /// ownership, or exact quantum/resource exhaustion.
    pub fn charge_execution_quantum(&mut self) -> Result<(), LifecycleApiError> {
        if self.retirement != GenerationResourceRetirement::Active {
            return Err(terminal_attempt_operational_error(
                "QEMU attempt generation owner is already terminal",
            ));
        }
        self.guard.charge_execution_quantum().map_err(|error| {
            attempt_operational_error("charge QEMU generation execution quantum", error)
        })
    }
}

impl<G> Drop for QemuAttemptGenerationResourceOwner<G>
where
    G: QemuAttemptResourceGuard,
{
    fn drop(&mut self) {
        self.quarantine();
    }
}

#[derive(Debug)]
struct QemuAttemptGenerationState {
    nodes: Vec<GenerationNodeState>,
    abandoned: bool,
}

/// Linear release token for one exact production VM process generation.
#[must_use = "finish the generation lease only after exact QEMU reap"]
pub struct QemuAttemptGenerationLease {
    identity: ProductionVmNodeGeneration,
    generations: Arc<Mutex<QemuAttemptGenerationState>>,
    previous_generation: Option<u64>,
    finished: bool,
}

impl fmt::Debug for QemuAttemptGenerationLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QemuAttemptGenerationLease")
            .field("identity", &self.identity)
            .field("previous_generation", &self.previous_generation)
            .field("finished", &self.finished)
            .finish_non_exhaustive()
    }
}

impl QemuAttemptGenerationLease {
    /// Aborts a generation whose launch left no live or unreaped process.
    ///
    /// This is the only path that rolls back the latest-generation fence. It is
    /// reserved for the launcher that still owns proof that process spawn never
    /// happened or that every spawned child was synchronously reaped. A normal
    /// launched generation must instead remain monotone and use
    /// [`ProductionVmNodeLease::finish`] after reap.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError::LoopFactory`] when the registry is poisoned,
    /// this is no longer the exact active/latest generation, or the lease was
    /// already finished. Failure leaves the lease fail-closed so its `Drop`
    /// path poisons aggregate release.
    pub(crate) fn abort_without_process(mut self) -> Result<(), LifecycleApiError> {
        if self.finished {
            return Err(generation_error(
                "cannot abort an already-finished QEMU generation lease",
            ));
        }
        let mut state = self
            .generations
            .lock()
            .map_err(|_| generation_error("QEMU attempt generation registry is poisoned"))?;
        let index = state
            .nodes
            .binary_search_by(|row| row.node.cmp(self.identity.node()))
            .ok();
        let active = index.and_then(|index| {
            let row = &state.nodes[index];
            (row.latest == Some(self.identity.generation()))
                .then(|| {
                    row.active
                        .iter()
                        .position(|generation| *generation == Some(self.identity.generation()))
                })
                .flatten()
        });
        let (Some(index), Some(active)) = (index, active) else {
            state.abandoned = true;
            return Err(generation_error(format!(
                "QEMU node `{}` generation {} is not the exact pending generation",
                self.identity.node().name,
                self.identity.generation(),
            )));
        };
        state.nodes[index].active[active] = None;
        state.nodes[index].latest = self.previous_generation;
        self.finished = true;
        Ok(())
    }
}

impl ProductionVmNodeLease for QemuAttemptGenerationLease {
    fn identity(&self) -> &ProductionVmNodeGeneration {
        &self.identity
    }

    fn open_checkpoint_root_overlay(&self) -> Result<std::fs::File, LifecycleApiError> {
        Err(generation_error(
            "generation lease has no pinned run-directory authority",
        ))
    }

    fn finish(&mut self) -> Result<(), LifecycleApiError> {
        if self.finished {
            return Ok(());
        }
        let mut state = self
            .generations
            .lock()
            .map_err(|_| generation_error("QEMU attempt generation registry is poisoned"))?;
        let active = state
            .nodes
            .binary_search_by(|row| row.node.cmp(self.identity.node()))
            .ok()
            .and_then(|index| {
                state.nodes[index]
                    .active
                    .iter()
                    .position(|generation| *generation == Some(self.identity.generation()))
                    .map(|active| (index, active))
            });
        let Some((index, active)) = active else {
            state.abandoned = true;
            return Err(generation_error(format!(
                "QEMU node `{}` generation {} has no active lease",
                self.identity.node().name,
                self.identity.generation(),
            )));
        };
        state.nodes[index].active[active] = None;
        self.finished = true;
        Ok(())
    }
}

impl Drop for QemuAttemptGenerationLease {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        match self.generations.lock() {
            Ok(mut state) => state.abandoned = true,
            Err(poisoned) => poisoned.into_inner().abandoned = true,
        }
    }
}

#[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
impl<G: QemuAttemptProcessResourceGuard> QemuAttemptGenerationResourceOwner<G> {
    /// Retains the same account's Cleanup for physical Park disposition.
    ///
    /// # Errors
    /// Refuses unavailable original custody or the retained Cleanup policy.
    pub(crate) fn retain_parent_park_cleanup(
        &self,
    ) -> Result<crucible_qemu_host::OriginalParentParkCleanup, QemuVmRealizationError> {
        self.guard.retain_parent_park_cleanup()
    }

    /// Checks actual Node, host and Preparation custody before publication.
    ///
    /// # Errors
    /// Refuses absent or different original physical custody without effects.
    pub(crate) fn verify_parent_park_binding(
        &self,
        source: &crucible_qemu_host::QemuNodeSetPreparedHotForkSource<'_>,
        original: &Arc<crucible_host_resources::host_supervision::HostOperationGuard>,
        decoder: &crucible_qemu_host::OriginalActorParkCaller,
    ) -> Result<(), crucible_qemu_host::OriginalActorParkQuiescenceError> {
        self.guard
            .verify_parent_park_binding(source, original, decoder)
    }

    pub(crate) fn enter_parent_park_quiescence(
        &self,
        source: &crucible_qemu_host::QemuNodeSetPreparedHotForkSource<'_>,
        original: &Arc<crucible_host_resources::host_supervision::HostOperationGuard>,
        decoder: &crucible_qemu_host::OriginalActorParkCaller,
    ) -> Result<
        crucible_qemu_host::OriginalActorParkQuiescence,
        crucible_qemu_host::OriginalActorParkQuiescenceError,
    > {
        self.guard
            .enter_parent_park_quiescence(source, original, decoder)
    }

    pub(crate) fn prepare_parent_park_imports(
        &self,
        source: &crucible_qemu_host::QemuNodeSetPreparedHotForkSource<'_>,
        original: &Arc<crucible_host_resources::host_supervision::HostOperationGuard>,
        decoder: &crucible_qemu_host::OriginalActorParkCaller,
        actor: &crucible_host_resources::host_supervision::HostOperationGuard,
        family: &crucible_host_resources::host_supervision::HostOperationGuard,
    ) -> Result<crucible_qemu_host::OriginalActorParkImports, crucible_qemu_host::OriginalActorParkImportError>
    {
        self.guard
            .prepare_parent_park_imports(source, original, decoder, actor, family)
    }
}

#[cfg(target_os = "linux")]
impl<G: QemuAttemptProcessResourceGuard> QemuAttemptGenerationResourceOwner<G> {
    /// Reserves the selected Source's actual copied-contract control lease.
    ///
    /// # Errors
    /// Refuses terminal ownership, a foreign node/contract or exhausted payer.
    pub(crate) fn reserve_contract_controls_for_node(
        &self,
        node: &NodeId,
        contract: &QemuChildProcessContract,
        descriptors: u64,
        bytes: u64,
    ) -> Result<
        crucible_host_resources::host_services::process_birth::SourceHostControlLease,
        QemuVmRealizationError,
    > {
        if self.retirement != GenerationResourceRetirement::Active {
            return Err(QemuVmRealizationError::ExecutorUnavailable {
                operation: "reserve retired generation contract controls",
                message: String::from("generation ownership is terminal"),
            });
        }
        self.guard
            .reserve_contract_controls_for_node(node, contract, descriptors, bytes)
    }
}

#[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
impl<G: QemuAttemptProcessResourceGuard> QemuAttemptGenerationResourceOwner<G> {
    /// Routes the saved Park phase through its actual selected member.
    ///
    /// # Errors
    /// Preserves unavailable node/physical custody and the same original postcut.
    pub(crate) fn retain_parent_park_cleanup_for_node(
        &self,
        node: &NodeId,
    ) -> Result<crucible_qemu_host::OriginalParentParkCleanup, QemuVmRealizationError> {
        self.guard.retain_parent_park_cleanup_for_node(node)
    }
}

#[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
impl<G: QemuAttemptProcessResourceGuard> QemuAttemptGenerationResourceOwner<G> {
    /// Routes the saved Park phase through its actual selected member.
    ///
    /// # Errors
    /// Preserves unavailable node/physical custody and the same original postcut.
    pub(crate) fn verify_parent_park_binding_for_node(
        &self,
        node: &NodeId,
        source: &crucible_qemu_host::QemuNodeSetPreparedHotForkSource<'_>,
        original: &Arc<crucible_host_resources::host_supervision::HostOperationGuard>,
        decoder: &crucible_qemu_host::OriginalActorParkCaller,
    ) -> Result<(), crucible_qemu_host::OriginalActorParkQuiescenceError> {
        self.guard
            .verify_parent_park_binding_for_node(node, source, original, decoder)
    }
}

#[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
impl<G: QemuAttemptProcessResourceGuard> QemuAttemptGenerationResourceOwner<G> {
    /// Routes the saved Park phase through its actual selected member.
    ///
    /// # Errors
    /// Preserves unavailable node/physical custody and the same original postcut.
    pub(crate) fn enter_parent_park_quiescence_for_node(
        &self,
        node: &NodeId,
        source: &crucible_qemu_host::QemuNodeSetPreparedHotForkSource<'_>,
        original: &Arc<crucible_host_resources::host_supervision::HostOperationGuard>,
        decoder: &crucible_qemu_host::OriginalActorParkCaller,
    ) -> Result<
        crucible_qemu_host::OriginalActorParkQuiescence,
        crucible_qemu_host::OriginalActorParkQuiescenceError,
    > {
        self.guard
            .enter_parent_park_quiescence_for_node(node, source, original, decoder)
    }
}

#[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
impl<G: QemuAttemptProcessResourceGuard> QemuAttemptGenerationResourceOwner<G> {
    /// Routes the saved Park phase through its actual selected member.
    ///
    /// # Errors
    /// Preserves unavailable node/physical custody and the same original postcut.
    pub(crate) fn prepare_parent_park_imports_for_node(
        &self,
        node: &NodeId,
        source: &crucible_qemu_host::QemuNodeSetPreparedHotForkSource<'_>,
        original: &Arc<crucible_host_resources::host_supervision::HostOperationGuard>,
        decoder: &crucible_qemu_host::OriginalActorParkCaller,
        actor: &crucible_host_resources::host_supervision::HostOperationGuard,
        family: &crucible_host_resources::host_supervision::HostOperationGuard,
    ) -> Result<crucible_qemu_host::OriginalActorParkImports, crucible_qemu_host::OriginalActorParkImportError>
    {
        self.guard
            .prepare_parent_park_imports_for_node(node, source, original, decoder, actor, family)
    }
}
