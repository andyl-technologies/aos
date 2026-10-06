//! Genuine component actors for scripted whole-world state-machine tests.
//!
//! These fixtures simulate native controller and pager facts explicitly. Their
//! resource ledger, service namespace, and original finite supervisor are real;
//! they do not qualify a Linux cgroup, project quota, or guest memory mapping.

use super::*;
use crucible_api::host_operational::HostResourceVector;
use crucible_linux_resource::host_supervision::{HostOperationBudgets, HostOperationSupervisor};

pub(super) struct ComponentRunner<R>(pub(super) R);

impl<R: CrucibleExecutionRunner> CrucibleExecutionRunner for ComponentRunner<R> {
    type Error = R::Error;

    fn execute(
        &mut self,
        input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
    ) -> Result<CrucibleExecutionOutcome, AttemptWorkerFailure<Self::Error>> {
        let admitted = service_context(
            context.resources(),
            context
                .runtime_basis()
                .expect("real queued execution basis"),
        );
        self.0.execute(input, &admitted)
    }

    fn reconcile_execution(
        &mut self,
        disposition: AttemptExecutionDisposition,
    ) -> Result<AttemptExecutionReconciliationStep, AttemptWorkerFailure<Self::Error>> {
        self.0.reconcile_execution(disposition)
    }

    fn quarantine_pending_execution(&mut self) {
        self.0.quarantine_pending_execution();
    }
}

pub(super) fn service_context(
    resources: AttemptResourceLimits,
    basis: AttemptExecutionRuntimeBasis,
) -> AttemptExecutionContext {
    admitted_service_context(resources, basis).with_component_ram_facts_for_test()
}

fn admitted_service_context(
    resources: AttemptResourceLimits,
    basis: AttemptExecutionRuntimeBasis,
) -> AttemptExecutionContext {
    let registry = crate::HostOperationalRegistry::default();
    registry
        .configure_bootstrap_limits(
            crucible_api::vm_lifecycle::HostRamBootstrapLimits::new(
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
    let cancellation = ExecutionCancellation::default();
    let watchdog = crate::supervision::AssignmentHostWatchdogGuard::start_service(
        supervision,
        cancellation.clone(),
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

    // Deliberate unresolved process fixtures can outlive their local runner.
    // Keep their original ledger and watcher through those quarantine paths.
    let _component_custody = Box::leak(Box::new((actor, watchdog)));
    context
}

#[test]
fn genuine_budget_owner_without_component_facts_requires_native_kernel_controller() {
    let registry_context = admitted_service_context(
        AttemptResourceLimits::new(8, 8 << 30, 8 << 30, 64).expect("request limits"),
        execution_basis(&execution_input(), 0xc2),
    );
    let factory =
        crate::qemu_campaign_lifecycle::create_host_ram_registration_factory(&registry_context)
            .expect("genuine service and finite cap");
    factory
        .configure_world(&[crucible_api::vm_lifecycle::ProductionHostRamLaunchShape {
            node: "component-node".into(),
            declared_ram_bytes: 16 * 1024 * 1024,
            vcpus: 1,
        }])
        .expect("complete admitted partition");
    assert!(factory.bind_native_resource_controller(None).is_err());
}
