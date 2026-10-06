//! Fresh Service authority for production checkpoint comparison and causal replay.
//!
//! Semantic limits come from the durable accepted attempt. Physical allocation,
//! native containment, RAM registration, watchdog and cleanup custody come from
//! a newly admitted full-resource Service on the same executor actor.

use super::*;
use crate::crucible_qemu_session::QemuAttemptResourceGuardBeginFailure as ReplayBeginFailure;
use crate::{QemuAttemptOperationalBoundary, QemuAttemptResourceGuard};
use crucible_api::vm_lifecycle::{
    ProductionHostRamLaunchShape, ProductionHostRamRegistrationFactory,
};
use crucible_qemu::{
    QemuChildProcessContract, QemuLaunchResourceRequirements, QemuNodeChild,
    QemuPreparedRunDirectory,
};

/// Retains fresh physical Service authority for one accepted-root comparison.
pub(crate) struct ProductionCheckpointReplayGuard<G: QemuAttemptProcessResourceGuard> {
    native: G,
    service: Option<crate::packaged_qemu_executor::RetainedTemplateService>,
    registration: Arc<dyn ProductionHostRamRegistrationFactory>,
    resources: AttemptResourceLimits,
    operation: crucible_linux_resource::host_supervision::HostOperationGuard,
    source: Arc<ScenarioDefForm>,
    supervisor: crucible_linux_resource::host_supervision::HostOperationSupervisor,
    completed_targets: u64,
    finished: bool,
    _decode_custody: crucible::owned_decode::DecodeCustody,
}

impl<G: QemuAttemptProcessResourceGuard> ProductionCheckpointReplayGuard<G> {
    pub(super) fn registration(&self) -> Arc<dyn ProductionHostRamRegistrationFactory> {
        Arc::clone(&self.registration)
    }

    pub(super) fn registration_preparation(
        &self,
    ) -> Result<
        Arc<dyn crucible_qemu::QemuReplayValidationRegistrationPreparation>,
        QemuVmRealizationError,
    > {
        let _original = self._decode_custody.enter();
        let budget = crucible::owned_decode::current_child_budget().map_err(model_copy)?;
        let _scope = budget
            .as_ref()
            .map(crucible::owned_decode::DecodeBudget::enter);
        crucible::owned_decode::charge_bytes(
            (std::mem::size_of::<ReplayRegistrationPreparation>()
                + 2 * std::mem::size_of::<usize>()) as u64,
        )
        .map_err(model_copy)?;
        Ok(Arc::new(ReplayRegistrationPreparation {
            registration: self.registration(),
            supervisor: self.supervisor.clone(),
            source: Arc::clone(&self.source),
            _decode_custody: self._decode_custody.clone(),
            _wrapper_custody: budget
                .as_ref()
                .map(crucible::owned_decode::DecodeBudget::custody)
                .unwrap_or_default(),
        }))
    }

    pub(super) fn target_completed(&mut self) -> Result<(), QemuVmRealizationError> {
        // Authorization to start a quantum is not completed work. Only the
        // caller's authenticated comparison and reap advance this inventory.
        self.completed_targets = self
            .completed_targets
            .checked_add(1)
            .ok_or_else(|| replay_contract("replay target count overflowed"))?;
        self.operation
            .progress(self.completed_targets)
            .map_err(|source| replay_contract(source.to_string()))
    }
}

struct ReplayRegistrationPreparation {
    registration: Arc<dyn ProductionHostRamRegistrationFactory>,
    supervisor: crucible_linux_resource::host_supervision::HostOperationSupervisor,
    source: Arc<ScenarioDefForm>,
    _decode_custody: crucible::owned_decode::DecodeCustody,
    _wrapper_custody: crucible::owned_decode::DecodeCustody,
}

impl crucible_qemu::QemuReplayValidationRegistrationPreparation for ReplayRegistrationPreparation {
    fn prepare(
        &self,
        config: &QemuLiveNodeStepGateConfig,
        node: &NodeId,
    ) -> Result<crucible_qemu::ram_control::RamControlRegistration, QemuVmRealizationError> {
        let vm = self
            .source
            .world()
            .vm_nodes()
            .into_iter()
            .find(|vm| &vm.id == node)
            .ok_or_else(|| {
                replay_contract("replay node does not belong to the authenticated World")
            })?;
        self.registration
            .prepare(
                &node.name,
                config.process_generation(),
                u64::from(vm.memory_mib) * 1024 * 1024,
                u32::from(vm.smp_vcpus),
            )
            .map_err(|source| replay_contract(source.to_string()))
    }

    fn supervisor(&self) -> crucible_linux_resource::host_supervision::HostOperationSupervisor {
        self.supervisor.clone()
    }
}

impl<G: QemuAttemptProcessResourceGuard> QemuAttemptOperationalBoundary
    for ProductionCheckpointReplayGuard<G>
{
    fn resource_limits(&self) -> AttemptResourceLimits {
        self.resources
    }

    fn cancellation(&self) -> &ExecutionCancellation {
        self.native.cancellation()
    }

    fn check_operational_boundary(&mut self) -> Result<(), QemuVmRealizationError> {
        self.operation
            .wait_slice()
            .map_err(|source| replay_contract(source.to_string()))?;
        self.native.check_operational_boundary()
    }

    fn charge_execution_quantum(&mut self) -> Result<(), QemuVmRealizationError> {
        self.native.charge_execution_quantum()
    }
}

impl<G: QemuAttemptProcessResourceGuard> QemuAttemptResourceGuard
    for ProductionCheckpointReplayGuard<G>
{
    fn finish(&mut self) -> Result<(), QemuVmRealizationError> {
        if self.finished {
            return Ok(());
        }
        if self.service.is_none() {
            return Err(replay_contract("replay cleanup authority was quarantined"));
        }
        self.native.finish()?;
        let completed = self
            .operation
            .complete()
            .map_err(|source| replay_contract(source.to_string()));
        if let Some(service) = self.service.as_ref() {
            service
                .release_after_world_cleanup()
                .map_err(|source| replay_contract(source.to_string()))?;
        }
        self.service = None;
        self.finished = true;
        completed.map(|_| ())
    }

    fn quarantine(&mut self) {
        self.native.quarantine();
        if let Some(service) = self.service.take() {
            service.retain_after_unknown_cleanup();
        }
    }
}

impl<G: QemuAttemptProcessResourceGuard> QemuAttemptProcessResourceGuard
    for ProductionCheckpointReplayGuard<G>
{
    fn native_resource_controller(
        &mut self,
    ) -> Result<Option<crucible_qemu::LinuxQemuNativeResourceController>, QemuVmRealizationError>
    {
        self.native.native_resource_controller()
    }

    fn child_process_contract(&self) -> Result<&QemuChildProcessContract, QemuVmRealizationError> {
        self.native.child_process_contract()
    }

    fn prepare_generation_run_directory(
        &mut self,
        requirements: QemuLaunchResourceRequirements,
    ) -> Result<QemuPreparedRunDirectory, QemuVmRealizationError> {
        self.native.prepare_generation_run_directory(requirements)
    }

    fn retain_failed_launch_child(&mut self, child: QemuNodeChild) {
        self.native.retain_failed_launch_child(child);
    }
}

impl<G: QemuAttemptProcessResourceGuard> Drop for ProductionCheckpointReplayGuard<G> {
    fn drop(&mut self) {
        if self.service.is_some() {
            self.quarantine();
        }
    }
}

impl<R> ProductionBakedGenesisReplayCatalogFactory<R> {
    pub(super) fn replay_service(
        &self,
        cancellation: &ExecutionCancellation,
        resources: AttemptResourceLimits,
        mut selected: Option<SelectedExactCheckpointRoot>,
    ) -> Result<crate::packaged_qemu_executor::RetainedTemplateService, ReplayBeginFailure> {
        let Some(basis) = self
            .replay_basis
            .as_ref()
            .filter(|basis| basis.resources() == resources)
        else {
            return Err(ReplayBeginFailure::before_checkpoint_claim(
                replay_contract("replay has no authenticated accepted execution basis"),
                selected,
            ));
        };
        let Some(services) = self.replay_services.as_ref() else {
            return Err(ReplayBeginFailure::before_checkpoint_claim(
                replay_contract("replay has no independently admitted Service allocator"),
                selected,
            ));
        };
        let checkpoint = selected.as_ref().map(|_| basis.checkpoint());
        services
            .start_for_replay_basis(basis, checkpoint, cancellation.clone(), &mut selected)
            .map_err(|source| {
                ReplayBeginFailure::before_checkpoint_claim(
                    replay_contract(source.to_string()),
                    selected,
                )
            })
    }
}

impl<R> ProductionBakedGenesisReplayCatalogFactory<R> {
    pub(super) fn begin_supervised_replay(
        &mut self,
        selected: SelectedExactCheckpointRoot,
        cancellation: &ExecutionCancellation,
        resources: AttemptResourceLimits,
    ) -> Result<ProductionCheckpointReplayGuard<R::Guard>, ReplayBeginFailure>
    where
        R: QemuAttemptResourceGuardFactory,
        R::Guard: QemuAttemptProcessResourceGuard,
    {
        let service = self.replay_service(cancellation, resources, Some(selected))?;
        let setup = (|| {
            let basis = self
                .replay_basis
                .as_ref()
                .ok_or_else(|| replay_contract("replay execution basis disappeared"))?;
            let operation = service
                .context()
                .host_operation_supervisor()
                .ok_or_else(|| replay_contract("replay Service supervision is unavailable"))?
                .begin_work(
                    crucible_linux_resource::host_supervision::HostOperationClass::Restore,
                    basis.source().world().vm_nodes().len() as u64,
                )
                .map_err(|source| replay_contract(source.to_string()))?;
            let registration =
                crate::qemu_campaign_lifecycle::create_host_ram_registration_factory(
                    service.native_context(),
                )
                .map_err(|source| replay_contract(source.to_string()))?;
            let _original = basis.custody().enter();
            let shape_budget =
                crucible::owned_decode::current_child_budget().map_err(model_copy)?;
            let _shape_scope = shape_budget
                .as_ref()
                .map(crucible::owned_decode::DecodeBudget::enter);
            let count = basis.source().world().vm_nodes().len();
            crucible::owned_decode::charge_array::<ProductionHostRamLaunchShape>(count)
                .map_err(model_copy)?;
            let mut shapes = Vec::new();
            shapes.try_reserve_exact(count).map_err(model_copy)?;
            for node in basis.source().world().vm_nodes() {
                crucible::owned_decode::charge_array::<u8>(node.id.name.len())
                    .map_err(model_copy)?;
                let mut name = String::new();
                name.try_reserve_exact(node.id.name.len())
                    .map_err(model_copy)?;
                name.push_str(&node.id.name);
                shapes.push(ProductionHostRamLaunchShape {
                    node: name,
                    declared_ram_bytes: u64::from(node.memory_mib) * 1024 * 1024,
                    vcpus: u32::from(node.smp_vcpus),
                });
            }
            registration
                .configure_world(&shapes)
                .map_err(|source| replay_contract(source.to_string()))?;
            let limits = registration
                .native_world_limits()
                .map_err(|source| replay_contract(source.to_string()))?;
            let native_resources = AttemptResourceLimits::new(
                limits.cpu_slots,
                limits.resident_bytes,
                limits.writable_bytes,
                resources.maximum_execution_quanta(),
            )
            .map_err(|source| replay_contract(source.to_string()))?;
            let source = basis.shared_source();
            let supervisor = service
                .context()
                .host_operation_supervisor()
                .cloned()
                .ok_or_else(|| replay_contract("replay Service supervision disappeared"))?;
            Ok((
                registration,
                native_resources,
                operation,
                source,
                supervisor,
                basis.custody(),
            ))
        })();
        let (registration, native_resources, operation, source, supervisor, custody) = match setup {
            Ok(setup) => setup,
            Err(error) => {
                return Err(ReplayBeginFailure::before_checkpoint_claim(
                    error,
                    service.context().take_selected_checkpoint(),
                ));
            }
        };

        let native = self.resources.begin(
            native_resources,
            cancellation.clone(),
            service.context().take_selected_checkpoint(),
        );
        let mut native = match native {
            Ok(native) => native,
            Err(failure) => {
                let (error, selected) = failure.into_parts();
                if selected.is_none() {
                    // No node may have reached the registry yet. Consuming
                    // its selection claim still signals uncertain native
                    // ownership, so an empty node ledger cannot discharge it.
                    service.retain_after_unknown_cleanup();
                }
                return Err(ReplayBeginFailure::before_checkpoint_claim(error, selected));
            }
        };
        let bind = (|| {
            registration
                .reserve_native_controller_resources()
                .map_err(|source| replay_contract(source.to_string()))?;
            let controller = native.native_resource_controller()?;
            registration
                .bind_native_resource_controller(controller)
                .map_err(|source| replay_contract(source.to_string()))
        })();
        if let Err(error) = bind {
            let cleanup = native.finish();
            if cleanup.is_err() {
                native.quarantine();
                service.retain_after_unknown_cleanup();
            }
            return Err(ReplayBeginFailure::before_checkpoint_claim(
                cleanup.err().unwrap_or(error),
                None,
            ));
        }
        Ok(ProductionCheckpointReplayGuard {
            native,
            service: Some(service),
            registration,
            resources,
            operation,
            source,
            supervisor,
            completed_targets: 0,
            finished: false,
            _decode_custody: custody,
        })
    }
}

/// Maps a host resource refusal without misclassifying it as guest evidence.
pub(super) fn replay_contract(message: impl Into<String>) -> QemuVmRealizationError {
    QemuVmRealizationError::ExecutorUnavailable {
        operation: "admit supervised checkpoint replay",
        message: message.into(),
    }
}

fn model_copy(source: impl std::error::Error + Send + Sync + 'static) -> QemuVmRealizationError {
    QemuVmRealizationError::ModelCopy {
        source: Box::new(source),
    }
}
