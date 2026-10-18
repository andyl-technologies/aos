//! Borrows replay's actual World guard from its original Main-owned constructor.
//!
//! Service, selected-root custody and native cleanup remain in that same role.
//! The local guard holds only selectors and scoped operation metadata; it never
//! forwards a borrowed launch contract or owns a replacement native guard.

use super::*;
use crate::lifecycle_cleanup::{
    PreparedSourceRetirement, ServiceMainHandle, ServiceMainReceiverHandle,
};
use crate::paused_checkpoint_promotion::{
    ProductionReplayBeginFailure, ProductionReplayCleanup, ProductionReplayError,
};
use crate::qemu_lifecycle_launcher::PreparedSourceHandle;
use crate::vm_lifecycle::ProductionHostRamRegistrationFactory;
use crucible_linux_resource::host_supervision::{
    HostOperationClass, HostOperationGuard, HostSupervisionError,
};

/// Measures only the selected generation storage retained by this replay World.
///
/// # Errors
/// Refuses invalid selected node geometry or extent overflow.
pub(crate) fn replay_world_control_bytes(
    source: &ScenarioDefForm,
) -> Result<u64, LifecycleApiError> {
    crate::QemuAttemptGenerationStorage::control_bytes(
        source.world().vm_nodes().iter().map(|node| &node.id),
    )
}

/// Selects one actual replay World while Main retains its native guard.
pub(crate) struct ProductionCheckpointReplayGuard<R>
where
    R: QemuAttemptResourceGuardFactory + Send + 'static,
    R::Guard: QemuAttemptProcessResourceGuard + Send + 'static,
{
    pub(super) prepared: PreparedSourceHandle<R>,
    service: ServiceMainHandle,
    receiver: Option<ServiceMainReceiverHandle>,
    registration: Option<Arc<dyn ProductionHostRamRegistrationFactory>>,
    resources: AttemptResourceLimits,
    cancellation: ExecutionCancellation,
    pub(super) operation: Option<HostOperationGuard>,
    source: Option<Arc<ScenarioDefForm>>,
    supervisor: Option<crucible_linux_resource::host_supervision::HostOperationSupervisor>,
    completed_targets: u64,
    body_closed: bool,
    post: Option<HostSupervisionError>,
    retirement: Option<PreparedSourceRetirement>,
    finished: bool,
    _decode_custody: crucible::owned_decode::DecodeCustody,
}

impl<R> ProductionCheckpointReplayGuard<R>
where
    R: QemuAttemptResourceGuardFactory + Send + 'static,
    R::Guard: QemuAttemptProcessResourceGuard + Send + 'static,
{
    pub(super) fn matches(
        &self,
        resources: AttemptResourceLimits,
        cancellation: &ExecutionCancellation,
    ) -> bool {
        self.resources == resources && self.cancellation.same_incarnation(cancellation)
    }

    pub(super) fn registration_preparation(
        &self,
        node: &NodeId,
    ) -> Result<
        Arc<dyn crucible_qemu::QemuReplayValidationRegistrationPreparation>,
        ProductionReplayError,
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
        let issuer = self
            .prepared
            .with_native(|native| native.installed_node_issuer_for_node(node))
            .map_err(|raw| {
                self.prepared
                    .failure_with_refusal("borrow replay node issuer", raw)
            })??;
        let registration = self
            .registration
            .as_ref()
            .ok_or_else(|| replay_contract("replay registration was retired"))?;
        let supervisor = self
            .supervisor
            .as_ref()
            .ok_or_else(|| replay_contract("replay supervisor was retired"))?;
        let source = self
            .source
            .as_ref()
            .ok_or_else(|| replay_contract("replay source was retired"))?;

        Ok(Arc::new(ReplayRegistrationPreparation {
            issuer,
            registration: Arc::clone(registration),
            supervisor: supervisor.clone(),
            source: Arc::clone(source),
            _decode_custody: self._decode_custody.clone(),
            _wrapper_custody: budget
                .as_ref()
                .map(crucible::owned_decode::DecodeBudget::custody)
                .unwrap_or_default(),
        }))
    }

    pub(super) fn target_completed(&mut self) -> Result<(), ProductionReplayError> {
        self.completed_targets = self
            .completed_targets
            .checked_add(1)
            .ok_or_else(|| replay_contract("replay target count overflowed"))?;
        let original = self
            .operation
            .as_ref()
            .ok_or_else(|| replay_contract("replay Restore was already completed"))?;
        if let Err(raw) = original.progress(self.completed_targets) {
            let role = match self
                .service
                .with_start(|start| start.record_external_supervision(raw))
            {
                Ok(()) => self.service.failure("record completed replay target"),
                Err(access) => self
                    .service
                    .failure_with_refusal("retain replay progress refusal", access),
            };
            return Err(ProductionReplayError::OriginalAdmission { first: raw, role });
        }
        Ok(())
    }

    fn dispose_aliases(&mut self) {
        self.registration = None;
        self.source = None;
        self.supervisor = None;
    }

    pub(super) fn finish(&mut self) -> Result<(), ProductionReplayCleanup> {
        if self.finished {
            return Ok(());
        }
        if !self.body_closed {
            self.body_closed = self.service.retry_prepared_body().map_err(|raw| {
                ProductionReplayCleanup::Prepared {
                    failure: self
                        .service
                        .failure_with_refusal("close replay native body", raw),
                    post: self.post,
                    progress: None,
                }
            })?;
            if !self.body_closed {
                return Err(ProductionReplayCleanup::Prepared {
                    failure: self.service.failure("replay native body remains retained"),
                    post: self.post,
                    progress: None,
                });
            }
        }
        // Taking the same Original records the once-only completion attempt.
        // Its negative post cannot reverse factual native body closure.
        if let Some(original) = self.operation.take() {
            self.post = original.complete().err();
        }
        self.dispose_aliases();
        if let Some(receiver) = self.receiver.take() {
            receiver.return_after_alias_destruction().map_err(|raw| {
                ProductionReplayCleanup::Prepared {
                    failure: self
                        .service
                        .failure_with_refusal("acknowledge replay alias destruction", raw),
                    post: self.post,
                    progress: None,
                }
            })?;
        }
        let retirement = self
            .retirement
            .get_or_insert_with(|| self.prepared.clone().into_retirement());
        let progress = retirement.retry();
        match progress {
            Ok(true) => {}
            progress => {
                return Err(ProductionReplayCleanup::Prepared {
                    failure: self
                        .service
                        .failure("replay World or Service return remains retained"),
                    post: self.post,
                    progress: progress.err(),
                });
            }
        }
        let Some(retirement) = self.retirement.take() else {
            return Err(ProductionReplayCleanup::Prepared {
                failure: self.service.failure("same replay retirement disappeared"),
                post: self.post,
                progress: None,
            });
        };
        let body = match retirement.finish() {
            Ok(body) => body,
            Err(retirement) => {
                self.retirement = Some(retirement);
                return Err(ProductionReplayCleanup::Prepared {
                    failure: self
                        .service
                        .failure("replay terminal payload remains borrowed"),
                    post: self.post,
                    progress: None,
                });
            }
        };
        self.finished = true;
        if body.first_failure().is_some() || self.post.is_some() {
            return Err(ProductionReplayCleanup::Returned {
                body,
                post: self.post,
            });
        }
        drop(body);
        Ok(())
    }
}

struct ReplayRegistrationPreparation {
    issuer: crucible_qemu::InstalledNodeLaunchIssuer,
    registration: Arc<dyn ProductionHostRamRegistrationFactory>,
    supervisor: crucible_linux_resource::host_supervision::HostOperationSupervisor,
    source: Arc<ScenarioDefForm>,
    _decode_custody: crucible::owned_decode::DecodeCustody,
    _wrapper_custody: crucible::owned_decode::DecodeCustody,
}

impl crucible_qemu::QemuReplayValidationRegistrationPreparation for ReplayRegistrationPreparation {
    fn launch_exact_node(
        &self,
        request: crucible_qemu::QemuProductionExactRestoreRequest,
    ) -> Result<
        crucible_qemu::QemuProductionExactRestoreLaunch,
        crucible_qemu::QemuLiveNodeStepGateError,
    > {
        self.issuer.launch_exact_node(request)
    }

    fn launch_fresh_node(
        &self,
        config: &crucible_qemu::QemuLiveNodeStepGateConfig,
        admission: crucible_qemu::QemuProductionFreshLaunchAdmission<'_>,
    ) -> Result<crucible_qemu::QemuNode, crucible_qemu::QemuLiveNodeStepGateError> {
        self.issuer.launch_fresh_node(config, admission)
    }

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

impl<R> Drop for ProductionCheckpointReplayGuard<R>
where
    R: QemuAttemptResourceGuardFactory + Send + 'static,
    R::Guard: QemuAttemptProcessResourceGuard + Send + 'static,
{
    fn drop(&mut self) {
        self.dispose_aliases();
        drop(self.operation.take());
        if let Some(receiver) = self.receiver.take() {
            // The exact aliases above are gone. Refusal keeps this token and
            // its recorded return cut in Main, rather than losing an owner.
            let _returned = receiver.return_after_alias_destruction();
        }
        if !self.finished && self.retirement.is_none() {
            self.retirement = Some(self.prepared.clone().into_retirement());
        }
    }
}

impl<R> ProductionBakedGenesisReplayCatalogFactory<R>
where
    R: QemuAttemptResourceGuardFactory + Clone + Send + 'static,
    R::Guard: QemuAttemptProcessResourceGuard + Send + 'static,
{
    pub(super) fn replay_service(
        &self,
        service: &ServiceMainHandle,
        cancellation: &ExecutionCancellation,
        resources: AttemptResourceLimits,
        selected: &mut Option<SelectedExactCheckpointRoot>,
    ) -> Result<(), ProductionReplayError> {
        let basis = self
            .replay_basis
            .as_ref()
            .filter(|basis| basis.resources() == resources)
            .ok_or_else(|| ProductionReplayError::Admission {
                first: replay_contract("replay has no authenticated accepted execution basis"),
                role: service.failure("authenticate replay Service basis"),
            })?;
        let services =
            self.replay_services
                .as_ref()
                .ok_or_else(|| ProductionReplayError::Admission {
                    first: replay_contract(
                        "replay has no independently admitted Service allocator",
                    ),
                    role: service.failure("select replay Service allocator"),
                })?;
        let checkpoint = selected.as_ref().map(|_| basis.checkpoint());
        if let Some(checkpoint) = checkpoint {
            match service.with_start(|start| {
                start.retain_reconciled_replay_root(checkpoint, || {
                    Ok::<_, std::convert::Infallible>(selected.take())
                })
            }) {
                Ok(Ok(Ok(()))) => {}
                Ok(Ok(Err(never))) => match never {},
                Ok(Err(_)) => {
                    return Err(service
                        .failure("retain actual replay selection in Main")
                        .into());
                }
                Err(raw) => {
                    return Err(service
                        .failure_with_refusal("borrow replay selection custody", raw)
                        .into());
                }
            }
        }
        match service.with_start(|start| {
            services.start_for_replay_basis(start, basis, checkpoint, cancellation.clone())
        }) {
            Ok(Ok(())) => Ok(()),
            Ok(Err(_)) => Err(service.failure("start replay Service").into()),
            Err(raw) => Err(service
                .failure_with_refusal("borrow replay Service startup", raw)
                .into()),
        }
    }

    pub(super) fn prepare_attempt_replay(
        &self,
        factory: &mut QemuAttemptProductionVmLifecycleFactory<R>,
        cancellation: &ExecutionCancellation,
        resources: AttemptResourceLimits,
    ) -> Result<(ProductionCheckpointReplayGuard<R>, AttemptExecutionContext), ProductionReplayError>
    {
        let service = factory.prepare_source_construction()?;
        let prepared = factory.prepared_source_handle().map_err(|raw| {
            service.failure_with_refusal("select original replay constructor", raw)
        })?;
        let mut selected = None;
        self.replay_service(&service, cancellation, resources, &mut selected)?;
        let custody = self
            .replay_basis
            .as_ref()
            .ok_or_else(|| ProductionReplayError::Admission {
                first: replay_contract("attempt replay basis disappeared"),
                role: service.failure("retain attempt replay decode basis"),
            })?
            .custody();
        let receiver = service
            .retain_receiver_in_main()
            .map_err(|raw| service.failure_with_refusal("retain attempt replay receiver", raw))?;
        let context = match service.with_ready(|ready| ready.context().clone()) {
            Ok(context) => context,
            Err(raw) => {
                let failure =
                    service.failure_with_refusal("project canonical attempt replay context", raw);
                let acknowledgment = receiver.return_after_alias_destruction().err();
                return Err(ProductionReplayError::Transport {
                    failure,
                    acknowledgment,
                });
            }
        };
        let guard = ProductionCheckpointReplayGuard {
            prepared,
            service,
            receiver: Some(receiver),
            registration: None,
            resources,
            cancellation: cancellation.clone(),
            operation: None,
            source: None,
            supervisor: None,
            completed_targets: 0,
            body_closed: false,
            post: None,
            retirement: None,
            finished: false,
            _decode_custody: custody,
        };
        Ok((guard, context))
    }

    pub(super) fn begin_supervised_replay(
        &mut self,
        selected: SelectedExactCheckpointRoot,
        cancellation: &ExecutionCancellation,
        resources: AttemptResourceLimits,
    ) -> Result<ProductionCheckpointReplayGuard<R>, ProductionReplayBeginFailure> {
        let mut selected = Some(selected);
        match self.begin_supervised_replay_inner(cancellation, resources, &mut selected) {
            Ok(guard) => Ok(guard),
            Err(first) => Err(ProductionReplayBeginFailure::new(first, selected)),
        }
    }

    fn begin_supervised_replay_inner(
        &mut self,
        cancellation: &ExecutionCancellation,
        resources: AttemptResourceLimits,
        selected: &mut Option<SelectedExactCheckpointRoot>,
    ) -> Result<ProductionCheckpointReplayGuard<R>, ProductionReplayError> {
        let config = self
            .savepoint_replay_config
            .as_ref()
            .ok_or_else(|| replay_contract("replay lifecycle configuration is unavailable"))?;
        let mut factory =
            QemuAttemptProductionVmLifecycleFactory::new(config.clone(), self.resources.clone());
        let service = factory.prepare_source_construction()?;
        let prepared = factory.prepared_source_handle().map_err(|raw| {
            service.failure_with_refusal("select original replay constructor", raw)
        })?;
        if let Err(first) = self.replay_service(&service, cancellation, resources, selected) {
            // The actual Main prepared body and any admitted Service remain
            // durable; the returned typed report keeps the initiating cause.
            drop(prepared.into_retirement());
            return Err(first);
        }
        let custody = self
            .replay_basis
            .as_ref()
            .ok_or_else(|| ProductionReplayError::Admission {
                first: replay_contract("replay basis disappeared"),
                role: service.failure("retain replay decode basis"),
            })?
            .custody();
        let receiver = service
            .retain_receiver_in_main()
            .map_err(|raw| service.failure_with_refusal("retain replay alias receiver", raw))?;
        let mut guard = ProductionCheckpointReplayGuard {
            prepared,
            service,
            receiver: Some(receiver),
            registration: None,
            resources,
            cancellation: cancellation.clone(),
            operation: None,
            source: None,
            supervisor: None,
            completed_targets: 0,
            body_closed: false,
            post: None,
            retirement: None,
            finished: false,
            _decode_custody: custody,
        };
        let (context, native_context) = guard
            .service
            .with_ready(|ready| (ready.context().clone(), ready.native_context().clone()))
            .map_err(|raw| {
                guard
                    .service
                    .failure_with_refusal("project canonical replay contexts", raw)
            })?;
        let basis = self
            .replay_basis
            .as_ref()
            .ok_or_else(|| replay_contract("replay basis disappeared"))?;
        let prepared = guard.prepared.clone();
        let mut original_refusal = None;
        let mut original_access = None;
        let setup = prepared.with_pending(|pending| {
            pending.require_pristine_request()?;
            let supervisor = match context.host_operation_supervisor().cloned() {
                Some(supervisor) => supervisor,
                None => {
                    pending.record_construction_first(
                        crate::QemuAttemptProductionVmLifecycleError::ResourceInstallation(
                            replay_contract("replay Service supervision is unavailable"),
                        ),
                    );
                    return Err(());
                }
            };
            let original = match supervisor.begin_work(
                HostOperationClass::Restore,
                basis.source().world().vm_nodes().len() as u64,
            ) {
                Ok(original) => original,
                Err(raw) => {
                    original_refusal = Some(raw);
                    if let Err(access) = guard.service.with_start(|start| {
                        start.record_external_supervision(raw);
                    }) {
                        original_access = Some(access);
                    }
                    return Err(());
                }
            };
            guard.operation = Some(original);
            let registration =
                match crate::qemu_campaign_lifecycle::create_host_ram_registration_factory(
                    &native_context,
                ) {
                    Ok(registration) => registration,
                    Err(first) => {
                        pending.record_construction_first(
                            crate::QemuAttemptProductionVmLifecycleError::HostRamAdmission(first),
                        );
                        return Err(());
                    }
                };
            let native_config = match config.try_clone_admitted() {
                Ok(config) => config.with_host_ram_registration_factory(Arc::clone(&registration)),
                Err(first) => {
                    pending.record_construction_first(
                        crate::QemuAttemptProductionVmLifecycleError::ModelCopy(Box::new(first)),
                    );
                    return Err(());
                }
            };
            guard.registration = Some(registration);
            guard.source = Some(basis.shared_source());
            guard.supervisor = Some(supervisor);
            pending.begin_replay_world(&native_context, basis.source(), &native_config)
        });
        // The canonical selected claim remains in Main's actual Service
        // context. These projections intentionally carry no duplicate claim.
        drop(native_context);
        drop(context);
        if let Some(first) = original_refusal {
            let role = match original_access {
                Some(access) => guard
                    .prepared
                    .failure_with_refusal("retain original replay Restore admission", access),
                None => guard.prepared.failure("admit original replay Restore"),
            };
            return Err(ProductionReplayError::OriginalAdmission { first, role });
        }
        match setup {
            Ok(Ok(())) => Ok(guard),
            Ok(Err(())) => Err(guard
                .prepared
                .failure("prepare supervised replay World")
                .into()),
            Err(raw) => Err(guard
                .prepared
                .failure_with_refusal("borrow original replay constructor", raw)
                .into()),
        }
    }
}

/// Maps an operational refusal without attributing it to guest evidence.
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
