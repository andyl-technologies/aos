//! Genuine component actors for scripted whole-world state-machine tests.
//!
//! These fixtures simulate native controller and pager facts explicitly. Their
//! resource ledger, service namespace, and original finite supervisor are real;
//! they do not qualify a Linux cgroup, project quota, or guest memory mapping.

use super::*;
use crucible_control_api::host_operational::HostResourceVector;
use crucible_host_resources::host_supervision::{HostOperationBudgets, HostOperationSupervisor};

/// Retains the actual watcher until all component contexts and guards return.
pub(super) struct ComponentService {
    // Stop and join the watcher before releasing its original capacity actor.
    _watchdog: crate::supervision::AssignmentHostWatchdogGuard,
    _actor: crate::executor_pool::PreparedExecutorActor<
        MemoryAssignmentLedger,
        crate::executor_supervisor::AllowAllAttemptAdmission,
    >,
}

/// Drops the context's registry aliases before its last service reference.
pub(super) struct ComponentContext {
    context: AttemptExecutionContext,
    service: Arc<ComponentService>,
}

impl std::ops::Deref for ComponentContext {
    type Target = AttemptExecutionContext;

    fn deref(&self) -> &Self::Target {
        &self.context
    }
}

impl ComponentContext {
    pub(super) fn with_resume_checkpoint(mut self, checkpoint: Option<ExactCheckpointId>) -> Self {
        self.context = self.context.with_resume_checkpoint(checkpoint);
        self
    }

    pub(super) fn with_start_mode(mut self, mode: AttemptStartMode) -> Self {
        self.context = self.context.with_start_mode(mode);
        self
    }
}

struct BoundComponentService {
    cancellation: ExecutionCancellation,
    service: Arc<ComponentService>,
}

/// Shares one factory's current incarnation with its actual execution adapter.
#[derive(Clone, Default)]
pub(super) struct ComponentBinding {
    current: Arc<Mutex<Option<BoundComponentService>>>,
}

impl ComponentBinding {
    fn bind(&self, context: &ComponentContext) {
        let next = BoundComponentService {
            cancellation: context.cancellation().clone(),
            service: Arc::clone(&context.service),
        };
        let displaced = {
            let mut current = self.current.lock().expect("component binding poisoned");
            current.replace(next)
        };
        // Final release can join the real watcher. It must not hold this mutex;
        // old quarantined guards retain their own immutable service reference.
        drop(displaced);
    }

    pub(super) fn retain(
        &self,
        cancellation: &ExecutionCancellation,
    ) -> Result<Arc<ComponentService>, QemuVmRealizationError> {
        let current = self
            .current
            .lock()
            .map_err(|_| test_realization_error("component binding poisoned"))?;
        let bound = current
            .as_ref()
            .filter(|bound| bound.cancellation.same_incarnation(cancellation))
            .ok_or_else(|| test_realization_error("component service incarnation is not bound"))?;
        Ok(Arc::clone(&bound.service))
    }
}

impl<S, O> QemuProductionHotForkWorldLifecycleFactory<S, ScriptedWorldGuardFactory, O>
where
    S: QemuHotForkSourceWorldProvider,
    O: crate::qemu_hot_fork_world_factory::target_operations::WorldTargetOperations<
            ScriptedWorldGuardFactory,
        >,
{
    /// Binds this exact owned context before the shared transaction can begin.
    pub(super) fn try_start_component(
        &mut self,
        input: &CrucibleAttemptExecution,
        context: &ComponentContext,
    ) -> Result<
        QemuHotForkWorldLifecycleStart<O::Lifecycle>,
        AttemptWorkerFailure<QemuProductionHotForkWorldLifecycleFactoryError<S::Error>>,
    > {
        self.resources.component.bind(context);
        self.try_start(input, &context.context)
    }

    pub(super) fn bind_component_context(&self, context: &ComponentContext) {
        self.resources.component.bind(context);
    }

    pub(super) fn component_binding(&self) -> ComponentBinding {
        self.resources.component.clone()
    }
}

pub(super) struct ComponentRunner<R> {
    runner: R,
    binding: ComponentBinding,
}

impl<R> ComponentRunner<R> {
    pub(super) fn new(runner: R, binding: ComponentBinding) -> Self {
        Self { runner, binding }
    }
}

impl<R: CrucibleExecutionRunner> CrucibleExecutionRunner for ComponentRunner<R> {
    type Error = R::Error;

    fn execute(
        &mut self,
        input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
    ) -> Result<CrucibleExecutionOutcome, AttemptWorkerFailure<Self::Error>> {
        let mut admitted = admitted_service_context_with_cancellation(
            context.resources(),
            context
                .runtime_basis()
                .expect("real queued execution basis"),
            context.cancellation().clone(),
        );
        admitted.context = admitted.context.with_component_ram_facts_for_test();
        self.binding.bind(&admitted);
        self.runner.execute(input, &admitted.context)
    }

    fn reconcile_execution(
        &mut self,
        disposition: AttemptExecutionDisposition,
    ) -> Result<AttemptExecutionReconciliationStep, AttemptWorkerFailure<Self::Error>> {
        self.runner.reconcile_execution(disposition)
    }

    fn try_retire_original(
        &mut self,
        original: &crucible_host_resources::host_supervision::HostOperationGuard,
    ) -> Result<(), Self::Error> {
        self.runner.try_retire_original(original)
    }

    fn quarantine_pending_execution(&mut self) {
        self.runner.quarantine_pending_execution();
    }
}

pub(super) fn service_context(
    resources: AttemptResourceLimits,
    basis: AttemptExecutionRuntimeBasis,
) -> ComponentContext {
    let mut admitted = admitted_service_context(resources, basis);
    admitted.context = admitted.context.with_component_ram_facts_for_test();
    admitted
}

fn admitted_service_context(
    resources: AttemptResourceLimits,
    basis: AttemptExecutionRuntimeBasis,
) -> ComponentContext {
    admitted_service_context_with_cancellation(resources, basis, ExecutionCancellation::default())
}

fn admitted_service_context_with_cancellation(
    resources: AttemptResourceLimits,
    basis: AttemptExecutionRuntimeBasis,
    cancellation: ExecutionCancellation,
) -> ComponentContext {
    let registry = crate::HostOperationalRegistry::default();
    registry
        .configure_bootstrap_limits(
            crucible_control_api::host_operational::HostRamBootstrapLimits::new(
                128,
                4096,
                16,
                128,
                32 * 1024 * 1024,
            )
            .expect("explicit component native and host-service entitlements"),
        )
        .expect("component bootstrap contract");
    let epoch = DaemonEpoch::from_bytes([0xc1; 16]).expect("component daemon");
    let ceiling = HostResourceVector {
        resident_peak_bytes: 32 << 30,
        backing_peak_bytes: 64 << 30,
        metadata_bytes: 16 << 30,
        staging_bytes: 8 << 30,
        paging_io_slots: 32,
        cpu_slots: 32,
        task_slots: 8192,
        file_descriptors: 131072,
    };
    let supervisor = LocalExecutorSupervisor::new(
        MemoryAssignmentLedger::default(),
        crate::executor_supervisor::AllowAllAttemptAdmission,
        epoch,
        ExecutorCapacity::new(16, 128, 256 << 30, 512 << 30, 1_000_000)
            .expect("complete component aggregate"),
    )
    .with_host_operational_capacity(
        crate::HostOperationalCapacity::new(128, 32768, 1_048_576, 128 << 30, 64 << 30)
            .expect("component operational capacity"),
    )
    .expect("actual operational capacity")
    .with_host_assignment_resources(ceiling, resources, 1024 * 1024)
    .expect("authored assignment peak and semantic request limits")
    .with_host_operational_registry(registry.clone())
    .expect("actual registry owner");
    let actor = crate::executor_pool::PreparedExecutorActor::new(supervisor)
        .expect("actual component capacity actor");
    let supervision = HostOperationSupervisor::new(
        HostOperationBudgets::default(),
        Some(Duration::from_secs(600)),
    )
    .expect("original finite component service cap");
    let owner = supervision.cap_id();
    let mut owner_id = [0_u8; 32];
    owner_id.copy_from_slice(&owner);
    registry
        .reserve_service_with_assignment_headroom(owner_id, ceiling, ceiling)
        .expect("actual service reservation");
    let mut node_ceiling = ceiling;
    node_ceiling.resident_peak_bytes -= 1024 * 1024;
    node_ceiling.task_slots -= 1;
    registry
        .configure_owner(
            crate::host_operational_registry::operational_identity(epoch.as_bytes()),
            owner_id,
            node_ceiling,
        )
        .expect("immutable component node subset excludes its watcher");
    let watchdog = crate::supervision::AssignmentHostWatchdogGuard::start_service(
        supervision,
        cancellation.clone(),
        None,
    )
    .expect("actual finite service watcher");
    let context = AttemptExecutionContext::for_preparation_service(
        resources,
        registry,
        crate::host_operational_registry::operational_identity(epoch.as_bytes()),
        owner_id,
        watchdog.state.clone(),
        cancellation,
    )
    .expect("genuinely admitted component context")
    .with_runtime_basis(basis);

    ComponentContext {
        context,
        service: Arc::new(ComponentService {
            _watchdog: watchdog,
            _actor: actor,
        }),
    }
}

#[test]
fn genuine_budget_owner_without_component_facts_requires_native_kernel_controller() {
    let _metadata_scope = component_metadata_scope();
    let registry_context = admitted_service_context(
        AttemptResourceLimits::new(8, 8 << 30, 8 << 30, 64).expect("request limits"),
        execution_basis(&execution_input(), 0xc2),
    );
    let factory =
        crate::qemu_campaign_lifecycle::create_host_ram_registration_factory(&registry_context)
            .expect("genuine service and finite cap");
    factory
        .configure_world(&[
            crucible_control_api::host_operational::ProductionHostRamLaunchShape {
                node: "component-node".into(),
                declared_ram_bytes: 16 * 1024 * 1024,
                vcpus: 1,
            },
        ])
        .expect("complete admitted partition");
    assert!(
        factory
            .bind_native_resource_controller("component-node", None)
            .is_err()
    );
}

#[test]
fn component_context_releases_its_actual_service_when_unborrowed() {
    let _metadata_scope = component_metadata_scope();
    let input = execution_input();
    let context = service_context(
        AttemptResourceLimits::new(8, 8 << 30, 8 << 30, 64).expect("resources"),
        execution_basis(&input, 0xe1),
    );
    let service = Arc::downgrade(&context.service);

    drop(context);

    assert!(service.upgrade().is_none());
}

#[test]
fn direct_component_start_binds_the_same_cancellation_before_guard_birth() {
    let _metadata_scope = component_metadata_scope();
    let input = execution_input();
    let context = execution_context(&input, 0xe2);
    let service = Arc::downgrade(&context.service);
    let cancellation = context.cancellation().clone();
    let run_state = tempfile::tempdir().expect("run state");
    let mut factory = QemuProductionHotForkWorldLifecycleFactory::new(
        RecordingUnavailableSourceWorldProvider {
            checkouts: Arc::new(AtomicUsize::new(0)),
        },
        ScriptedWorldGuardFactory::new(ScriptedWorldObservations::new()),
        run_state.path(),
        QemuShutdownPolicy::fast_test(),
        QemuAsyncDriverPolicy::fast_test(),
    );

    assert!(matches!(
        factory.try_start_component(&input, &context),
        Ok(QemuHotForkWorldLifecycleStart::Declined)
    ));
    let guard = factory
        .resources
        .begin(context.resources(), cancellation.clone(), None)
        .expect("actual scripted guard retains bound service");
    assert!(guard.cancellation().same_incarnation(&cancellation));
    assert!(Arc::ptr_eq(&guard._component_service, &context.service));
    assert!(
        factory
            .resources
            .component
            .retain(&ExecutionCancellation::default())
            .is_err()
    );

    drop(context);
    drop(factory);
    assert!(service.upgrade().is_some());

    drop(guard);
    assert!(service.upgrade().is_none());
}

#[test]
fn displaced_service_survives_in_its_original_quarantined_guard() {
    let _metadata_scope = component_metadata_scope();
    let input = execution_input();
    let first = execution_context(&input, 0xe3);
    let second = execution_context(&input, 0xe4);
    let first_service = Arc::downgrade(&first.service);
    let second_service = Arc::downgrade(&second.service);
    let first_cancellation = first.cancellation().clone();
    let second_cancellation = second.cancellation().clone();
    let observations = ScriptedWorldObservations::new();
    let mut resources = ScriptedWorldGuardFactory::new(observations.clone());
    resources.component.bind(&first);
    let mut guard = resources
        .begin(first.resources(), first_cancellation.clone(), None)
        .expect("actual first guard");
    guard.quarantine();
    assert_eq!(observations.quarantines.load(Ordering::SeqCst), 1);

    resources.component.bind(&second);
    drop(first);
    assert!(first_service.upgrade().is_some());
    assert!(Arc::ptr_eq(
        &guard._component_service,
        &first_service
            .upgrade()
            .expect("quarantined original service")
    ));
    assert!(resources.component.retain(&first_cancellation).is_err());
    assert!(resources.component.retain(&second_cancellation).is_ok());
    first_cancellation.cancel();
    assert!(guard.cancellation().is_canceled());
    assert!(!second_cancellation.is_canceled());

    drop(second);
    drop(resources);
    assert!(second_service.upgrade().is_none());
    assert!(first_service.upgrade().is_some());

    drop(guard);
    assert!(first_service.upgrade().is_none());
    assert_eq!(observations.quarantines.load(Ordering::SeqCst), 1);
}

struct ComponentGuardProbe {
    resources: ScriptedWorldGuardFactory,
    cancellation: ExecutionCancellation,
    basis: AttemptExecutionRuntimeBasis,
    guard: Option<ScriptedWorldGuard>,
}

impl CrucibleExecutionRunner for ComponentGuardProbe {
    type Error = &'static str;

    fn execute(
        &mut self,
        _input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
    ) -> Result<CrucibleExecutionOutcome, AttemptWorkerFailure<Self::Error>> {
        assert_eq!(context.runtime_basis(), Some(self.basis));
        assert!(context.cancellation().same_incarnation(&self.cancellation));
        let mut guard = self
            .resources
            .begin(context.resources(), context.cancellation().clone(), None)
            .expect("real execution adapter binds the guard's exact service");
        guard.quarantine();
        self.guard = Some(guard);
        // This ownership probe publishes no modeled execution success.
        Err(AttemptWorkerFailure::Terminal("component guard retained"))
    }
}

#[test]
fn actual_component_runner_preserves_incoming_cancellation_and_incarnation() {
    let _metadata_scope = component_metadata_scope();
    let input = execution_input();
    let context = execution_context(&input, 0xe5);
    let cancellation = context.cancellation().clone();
    let resources = ScriptedWorldGuardFactory::new(ScriptedWorldObservations::new());
    let binding = resources.component.clone();
    let mut runner = ComponentRunner::new(
        ComponentGuardProbe {
            resources,
            cancellation: cancellation.clone(),
            basis: context.runtime_basis().expect("actual execution basis"),
            guard: None,
        },
        binding,
    );

    assert!(matches!(
        runner.execute(&input, &context),
        Err(AttemptWorkerFailure::Terminal("component guard retained"))
    ));
    let guard = runner.runner.guard.take().expect("actual retained guard");
    let service = Arc::downgrade(&guard._component_service);
    assert!(guard.cancellation().same_incarnation(&cancellation));

    drop(runner);
    assert!(service.upgrade().is_some());
    cancellation.cancel();
    assert!(guard.cancellation().is_canceled());

    drop(guard);
    assert!(service.upgrade().is_none());
}
