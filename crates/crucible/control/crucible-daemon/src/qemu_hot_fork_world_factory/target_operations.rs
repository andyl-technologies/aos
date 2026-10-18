//! Target resource operations used by the one whole-world fork transaction.
//!
//! Production consumes the retained Source's real permit and binds every child
//! to that same family. Component tests supply a separate resource model; they
//! cannot construct a native permit or select the model in a production build.
//! Checkout, launch, adoption, rollback and publication remain in the factory.

use super::*;
use crucible_host_resources::host_supervision::HostOperationSupervisor;
use crucible_qemu_host::QemuLaunchResourceRequirements;

/// Preserves the existing distinction between Source and target-begin refusal.
pub(crate) enum TargetBeginFailure {
    /// The retained Source could not lend its exact target permit.
    Source(String),
    /// The matching resource factory refused the target transaction.
    Resources(crate::crucible_qemu_session::QemuAttemptResourceGuardBeginReport),
}

/// Supplies resource effects without deciding any World transaction outcome.
///
/// Implementations cannot restore a checkout, publish an assembly, release the
/// aggregate or change failure classification. The shared orchestrator owns all
/// of those decisions. No method returns newly manufactured native authority.
pub(crate) trait WorldTargetOperations<R: QemuAttemptResourceGuardFactory + Send + 'static>
where
    R::Guard: QemuAttemptProcessResourceGuard + Send + 'static,
{
    /// Complete runtime produced by this backend's actual ownership path.
    type Lifecycle: QemuHotForkWorldLifecycleOwner;

    /// Constructs under the actual backend's containing owner.
    fn construct_world<S: QemuHotForkSourceWorldProvider>(
        factory: &mut QemuProductionHotForkWorldLifecycleFactory<S, R, Self>,
        input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
        selected: SelectedTargetSource,
    ) -> Result<
        QemuHotForkWorldLifecycleStart<Self::Lifecycle>,
        AttemptWorkerFailure<QemuProductionHotForkWorldLifecycleFactoryError<S::Error>>,
    >
    where
        Self: Sized;

    /// Recovers only the actual original source checkout after retirement.
    fn into_source_lease(
        lifecycle: Self::Lifecycle,
    ) -> Result<QemuHotForkSourceWorldLease, Self::Lifecycle>;

    /// Abandons a caller while preserving its backend's real cleanup owner.
    fn abandon_runtime(lifecycle: Self::Lifecycle);

    /// Binds each backend controller before any member launch.
    ///
    /// # Errors
    /// Reports the first controller reservation or binding refusal.
    fn bind_world(
        &self,
        guard: &mut R::Guard,
        ram: &dyn crate::vm_lifecycle::ProductionHostRamRegistrationFactory,
        input: &CrucibleAttemptExecution,
    ) -> Result<(), String>;

    /// Prepares one member's supervision and backend RAM ownership.
    ///
    /// # Errors
    /// Refuses missing original supervision or mismatched member ownership.
    fn prepare_member(
        &self,
        target: &mut QemuHotForkWorldNodeTarget<R::Guard>,
        context: &AttemptExecutionContext,
        ram: &dyn crate::vm_lifecycle::ProductionHostRamRegistrationFactory,
        node: &crucible_engine::NodeId,
        generation: u64,
        requirements: QemuLaunchResourceRequirements,
    ) -> Result<HostOperationSupervisor, String>;

    /// Prepares and provisions the member's privately owned child files.
    ///
    /// # Errors
    /// Preserves storage, custody and file-provisioning refusal.
    fn prepare_directory(
        &self,
        source_world: &Arc<Mutex<ProductionVmHotForkSourceWorld>>,
        target: &mut QemuHotForkWorldNodeTarget<R::Guard>,
        requirements: QemuLaunchResourceRequirements,
    ) -> Result<QemuPreparedRunDirectory, QemuVmRealizationError>;
}

/// Uses the genuine Source, target-family and RAM admission operations.
pub(crate) struct NativeTargetOperations;

impl<R> WorldTargetOperations<R> for NativeTargetOperations
where
    R: QemuAttemptResourceGuardFactory + Send + 'static,
    R::Guard: QemuAttemptProcessResourceGuard
        + QemuHotForkChildProcessOwner<Authority = LinuxQemuHotForkChildProcessAuthority>
        + Send
        + 'static,
{
    type Lifecycle = super::runtime::PreparedTargetRuntime<R>;

    fn construct_world<S: QemuHotForkSourceWorldProvider>(
        factory: &mut QemuProductionHotForkWorldLifecycleFactory<S, R, Self>,
        input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
        selected: SelectedTargetSource,
    ) -> Result<
        QemuHotForkWorldLifecycleStart<Self::Lifecycle>,
        AttemptWorkerFailure<QemuProductionHotForkWorldLifecycleFactoryError<S::Error>>,
    > {
        factory.start_retained_target(input, context, selected)
    }

    fn into_source_lease(
        lifecycle: Self::Lifecycle,
    ) -> Result<QemuHotForkSourceWorldLease, Self::Lifecycle> {
        lifecycle.into_source_lease()
    }

    fn abandon_runtime(lifecycle: Self::Lifecycle) {
        // The operation-only wrapper returns its actual body to Main on Drop.
        drop(lifecycle);
    }

    fn bind_world(
        &self,
        guard: &mut R::Guard,
        ram: &dyn crate::vm_lifecycle::ProductionHostRamRegistrationFactory,
        input: &CrucibleAttemptExecution,
    ) -> Result<(), String> {
        for node in input.scenario().world().vm_nodes() {
            // A sibling's controller cannot pay this member's descriptor window.
            ram.reserve_native_controller_resources(&node.id.name)
                .map_err(|error| error.to_string())?;
            let controller = guard
                .native_resource_controller_for_node(&node.id)
                .map_err(|error| error.to_string())?;
            ram.bind_native_resource_controller(&node.id.name, controller)
                .map_err(|error| error.to_string())?;
        }
        Ok(())
    }

    fn prepare_member(
        &self,
        target: &mut QemuHotForkWorldNodeTarget<R::Guard>,
        context: &AttemptExecutionContext,
        ram: &dyn crate::vm_lifecycle::ProductionHostRamRegistrationFactory,
        node: &crucible_engine::NodeId,
        generation: u64,
        requirements: QemuLaunchResourceRequirements,
    ) -> Result<HostOperationSupervisor, String> {
        #[cfg(test)]
        {
            target.component_ram_facts = context.uses_component_ram_facts();
        }
        let owner = context
            .host_operation_supervisor()
            .ok_or_else(|| String::from("hot-fork child has no admitted operational supervisor"))?;
        let (_, budgets) = owner.budgets().map_err(|error| error.to_string())?;
        let supervisor = owner
            .new_budget_owner(budgets)
            .map_err(|error| error.to_string())?;
        let registration = ram
            .prepare(
                &node.name,
                generation,
                requirements.guest_memory_bytes(),
                requirements.virtual_cpus(),
            )
            .map_err(|error| error.to_string())?;
        target
            .install_host_ram_registration(
                registration,
                supervisor.clone(),
                requirements.guest_memory_bytes(),
            )
            .map_err(|error| error.to_string())?;
        Ok(supervisor)
    }

    fn prepare_directory(
        &self,
        source_world: &Arc<Mutex<ProductionVmHotForkSourceWorld>>,
        target: &mut QemuHotForkWorldNodeTarget<R::Guard>,
        requirements: QemuLaunchResourceRequirements,
    ) -> Result<QemuPreparedRunDirectory, QemuVmRealizationError> {
        let contract = target.child_process_contract()?;
        let mut directory = source_world
            .lock()
            .map_err(|_| QemuVmRealizationError::Executor {
                operation: "prepare same-family hot-fork directory",
                message: String::from("source-world ownership lock is poisoned"),
            })?
            .prepare_fork_target_run_directory(contract, requirements)
            .map_err(|error| QemuVmRealizationError::Executor {
                operation: "prepare same-family hot-fork directory",
                message: error.to_string(),
            })?;
        let custody =
            target
                .host_ram_custody()
                .ok_or_else(|| QemuVmRealizationError::Executor {
                    operation: "retain hot-fork child RAM custody",
                    message: String::from("admitted child lost its exact launch custody"),
                })?;
        directory
            .retain_ram_launch_custody(custody.clone())
            .map_err(|source| QemuVmRealizationError::Executor {
                operation: "retain hot-fork child directory custody",
                message: source.to_string(),
            })?;
        directory
            .provision_hot_fork_child_files(target.child_process_contract()?)
            .map_err(|source| QemuVmRealizationError::Executor {
                operation: "provision private hot-fork child files",
                message: source.to_string(),
            })?;
        Ok(directory)
    }
}

/// Supplies component-only begin/custody operations without a native issuer.
#[cfg(test)]
pub(crate) trait ComponentWorldTargetOperations<R>: WorldTargetOperations<R>
where
    R: QemuAttemptResourceGuardFactory + Send + 'static,
    R::Guard: QemuAttemptProcessResourceGuard + Send + 'static,
{
    fn prepare_component_construction(
        &self,
    ) -> Result<Option<Box<crate::ProductionVmConstructionCustody>>, crucible_control_api::LifecycleApiError>;

    fn begin_target(
        &self,
        resources: &mut R,
        source_world: &Arc<Mutex<ProductionVmHotForkSourceWorld>>,
        limits: AttemptResourceLimits,
        cancellation: crate::ExecutionCancellation,
    ) -> Result<R::Guard, TargetBeginFailure>;
}
