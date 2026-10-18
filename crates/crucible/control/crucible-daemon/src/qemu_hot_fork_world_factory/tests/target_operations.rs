//! Component resource effects for the shared whole-world transaction.
//!
//! Scripted children are real fixture processes with actual pidfds, private
//! files and teardown observations. Their resource model has no native Source,
//! target-family permit, pager admission or project-quota authority. Keeping
//! these effects separate lets the production transaction exercise every
//! existing rollback, adoption and reuse assertion without forging an issuer.

use super::*;
use crate::qemu_hot_fork_world_factory::target_construction::TargetSetupFailure;
use crate::qemu_hot_fork_world_factory::target_operations::{
    TargetBeginFailure, WorldTargetOperations,
};
use crucible_control_api::host_operational::HostRamAdmissionError;
use crucible_host_resources::host_supervision::HostOperationSupervisor;

pub(super) struct ComponentTargetOperations;

impl WorldTargetOperations<ScriptedWorldGuardFactory> for ComponentTargetOperations {
    type Lifecycle = QemuProductionHotForkWorldLifecycle<ScriptedWorldGuard>;

    fn construct_world<S: QemuHotForkSourceWorldProvider>(
        factory: &mut QemuProductionHotForkWorldLifecycleFactory<
            S,
            ScriptedWorldGuardFactory,
            Self,
        >,
        input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
        selected: SelectedTargetSource,
    ) -> ProductionLifecycleStartResult<ScriptedWorldGuard, S::Error> {
        factory.try_start_component_world(
            input,
            context,
            selected.lease,
            selected.world,
            selected.continuation,
            selected.runtime_basis,
        )
    }

    fn into_source_lease(
        lifecycle: Self::Lifecycle,
    ) -> Result<QemuHotForkSourceWorldLease, Self::Lifecycle> {
        lifecycle
            .into_source_lease()
            .map_err(|lifecycle| *lifecycle)
    }

    fn abandon_runtime(mut lifecycle: Self::Lifecycle) {
        lifecycle.quarantine();
        let _retained_component = Box::leak(Box::new(lifecycle));
    }

    fn bind_world(
        &self,
        _guard: &mut ScriptedWorldGuard,
        _ram: &dyn crate::vm_lifecycle::ProductionHostRamRegistrationFactory,
        _input: &CrucibleAttemptExecution,
    ) -> Result<(), TargetSetupFailure> {
        // No native controller exists in this model. In particular this does
        // not publish a controller or return successful native admission.
        Ok(())
    }

    fn prepare_member(
        &self,
        _target: &mut QemuHotForkWorldNodeTarget<ScriptedWorldGuard>,
        context: &AttemptExecutionContext,
        _ram: &dyn crate::vm_lifecycle::ProductionHostRamRegistrationFactory,
        _node: &NodeId,
        _generation: u64,
        _requirements: QemuLaunchResourceRequirements,
    ) -> Result<HostOperationSupervisor, TargetSetupFailure> {
        if !context.uses_component_ram_facts() {
            return Err(HostRamAdmissionError::contract(
                "component target requires component RAM facts",
            )
            .into());
        }
        let owner = context.host_operation_supervisor().ok_or_else(|| {
            HostRamAdmissionError::contract("hot-fork child has no admitted operational supervisor")
        })?;
        let (_, budgets) = owner.budgets().map_err(HostRamAdmissionError::from)?;
        // Reuse the existing component supervision path. No RAM registration,
        // Source purpose or native launch-custody object is constructed here.
        Ok(owner
            .new_budget_owner(budgets)
            .map_err(HostRamAdmissionError::from)?)
    }

    fn prepare_directory(
        &self,
        _source_world: &Arc<Mutex<ProductionVmHotForkSourceWorld>>,
        target: &mut QemuHotForkWorldNodeTarget<ScriptedWorldGuard>,
        requirements: QemuLaunchResourceRequirements,
    ) -> Result<QemuPreparedRunDirectory, QemuVmRealizationError> {
        // The existing scripted guard owns the temporary filesystem. Preserve
        // its injected refusal and the actual directory/file observations.
        let mut directory = target.prepare_component_generation_run_directory(requirements)?;
        directory
            .provision_hot_fork_child_files(target.child_process_contract()?)
            .map_err(|source| QemuVmRealizationError::Executor {
                operation: "provision private hot-fork child files",
                message: source.to_string(),
            })?;
        Ok(directory)
    }
}

#[test]
fn default_target_backend_keeps_missing_native_issuer_refusal_before_component_effects() {
    let _metadata_scope = component_metadata_scope();
    let source =
        scripted_hot_fork_source_for_test(QemuTestHotForkOutcome::Forked).expect("scripted source");
    let source_process = source.process_id();
    let (_, source_world) = prepared_test_source_world(vec![source]).expect("prepared source");
    let input = execution_input();
    let key = QemuHotForkSourceWorldKey::new(
        input.lineage().id().expect("lineage"),
        source_world
            .continuation()
            .unwrap()
            .configuration()
            .def
            .id(),
        source_world.continuation().unwrap().configuration().id(),
        ExecutorCompatibilityProfile::from_lineage(input.lineage()),
    );
    let observations = ScriptedWorldObservations::new();
    let run_state = tempfile::tempdir().expect("run state");
    let mut factory = QemuProductionHotForkWorldLifecycleFactory::new(
        QemuSingleHotForkSourceWorldProvider::new(key, source_world),
        ScriptedWorldGuardFactory {
            observations: observations.clone(),
        },
        run_state.path(),
        QemuShutdownPolicy::fast_test(),
        QemuAsyncDriverPolicy::fast_test(),
    );

    let failure = factory
        .try_start(&input, &execution_context(&input, 0x9f))
        .err()
        .expect("the default backend requires a genuine native issuer");

    let AttemptWorkerFailure::Retryable(QemuProductionHotForkWorldLifecycleFactoryError::Source(
        message,
    )) = failure
    else {
        panic!("default native admission changed its refusal class");
    };
    assert!(message.contains("launcher has no genuine source target issuer"));
    assert!(factory.sources.available());
    assert_eq!(observations.finishes.load(Ordering::SeqCst), 0);
    assert_eq!(observations.quarantines.load(Ordering::SeqCst), 0);
    assert!(
        observations
            .prepared_run_directories
            .lock()
            .unwrap()
            .is_empty()
    );
    assert!(
        observations
            .retained_child_processes
            .lock()
            .unwrap()
            .is_empty()
    );
    assert!(linux_process_identity(source_process).unwrap().is_some());
}

impl
    crate::qemu_hot_fork_world_factory::target_operations::ComponentWorldTargetOperations<
        ScriptedWorldGuardFactory,
    > for ComponentTargetOperations
{
    fn prepare_component_construction(
        &self,
    ) -> Result<Option<Box<crate::ProductionVmConstructionCustody>>, crucible_control_api::LifecycleApiError>
    {
        crate::ProductionVmConstructionCustody::prepare_component().map(Some)
    }

    fn begin_target(
        &self,
        resources: &mut ScriptedWorldGuardFactory,
        _source_world: &Arc<Mutex<ProductionVmHotForkSourceWorld>>,
        limits: AttemptResourceLimits,
        cancellation: ExecutionCancellation,
    ) -> Result<ScriptedWorldGuard, TargetBeginFailure> {
        // This is the existing component owner, not a native target consumer.
        // The common transaction still checks its limits and cancellation.
        resources
            .begin(limits, cancellation, None)
            .map_err(|failure| {
                let (error, _) = failure.into_parts();
                TargetBeginFailure::Resources(error)
            })
    }
}
