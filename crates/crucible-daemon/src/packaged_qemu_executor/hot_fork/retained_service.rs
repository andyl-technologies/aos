//! Independently charged owners for the physical lifetime of retained worlds.

use super::*;
use crate::supervision::AssignmentHostWatchdogGuard;
use crucible_api::host_operational::{HostOperationalError, HostResourceVector};
use crucible_linux_resource::host_supervision::HostOperationSupervisor;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

/// Keeps the source's resource reservation and idle-safe supervision alive.
pub(crate) struct RetainedTemplateService {
    context: AttemptExecutionContext,
    native_context: AttemptExecutionContext,
    watchdog: Mutex<Option<AssignmentHostWatchdogGuard>>,
    registry: crate::HostOperationalRegistry,
    owner: [u8; 32],
    released: AtomicBool,
    preparation_custody: Arc<dyn Send + Sync>,
    _input_retention: Option<Arc<dyn Send + Sync>>,
}

#[derive(Clone)]
pub(crate) struct RetainedTemplateServiceFactory {
    config: PackagedQemuExecutorConfig,
    registry: crate::HostOperationalRegistry,
    preparation_custody: Arc<dyn Send + Sync>,
    input_retention: Option<Arc<dyn Send + Sync>>,
    outer_supervisor: Option<HostOperationSupervisor>,
}

enum ServiceHeadroom {
    FutureAssignment,
    AdmittedAssignment([u8; 32]),
}

enum ServicePurpose {
    RetainedTemplate,
    Replay,
}

impl RetainedTemplateServiceFactory {
    /// Admits a causal native oracle under the active accepted assignment.
    #[cfg(test)]
    pub(in crate::packaged_qemu_executor) fn start_causal_source_for_test(
        &self,
        scenario: &ScenarioDefForm,
        original: &AttemptExecutionContext,
    ) -> Result<RetainedTemplateService, PackagedQemuExecutorError> {
        self.start_comparison_for_test(scenario, original, true)
    }

    /// Charges an independent comparison child under the live accepted owner.
    ///
    /// This receipt authorizes a physical comparison Service; it does not
    /// manufacture another campaign assignment or another selected root.
    #[cfg(test)]
    pub(in crate::packaged_qemu_executor) fn start_comparison_child_for_test(
        &self,
        scenario: &ScenarioDefForm,
        original: &AttemptExecutionContext,
    ) -> Result<RetainedTemplateService, PackagedQemuExecutorError> {
        self.start_comparison_for_test(scenario, original, false)
    }

    #[cfg(test)]
    fn start_comparison_for_test(
        &self,
        scenario: &ScenarioDefForm,
        original: &AttemptExecutionContext,
        causal_source: bool,
    ) -> Result<RetainedTemplateService, PackagedQemuExecutorError> {
        let Some(crucible_api::host_operational::HostOuterCapOwner::Execution(owner)) =
            original.host_outer_cap_owner()
        else {
            return Err(HostOperationalError::Unavailable.into());
        };
        if original.host_daemon_epoch()
            != crate::host_operational_registry::operational_identity(
                self.config.daemon_epoch.as_bytes(),
            )
        {
            return Err(HostOperationalError::Unavailable.into());
        }

        let mut service = RetainedTemplateService::start(
            self,
            scenario,
            if causal_source {
                None
            } else {
                original.resume_checkpoint()
            },
            ServiceHeadroom::AdmittedAssignment(owner),
            if causal_source {
                ServicePurpose::RetainedTemplate
            } else {
                ServicePurpose::Replay
            },
            ExecutionCancellation::default(),
        )?;
        service.context = service.context.clone().with_semantic_resume_basis(original);
        if causal_source {
            service.context = service.context.clone().with_resume_checkpoint(None);
        }
        Ok(service)
    }

    pub(in crate::packaged_qemu_executor) fn new(
        preparation: &super::super::preparation::PackagedPreparation,
        config: &PackagedQemuExecutorConfig,
    ) -> Self {
        Self::from_owner(
            preparation.host_operational_registry.clone(),
            preparation.actor.preparation_custody(),
            config,
        )
    }

    /// Reuses the original charged actor and registry for native Service owners.
    pub(crate) fn from_owner(
        registry: crate::HostOperationalRegistry,
        custody: Arc<dyn Send + Sync>,
        config: &PackagedQemuExecutorConfig,
    ) -> Self {
        Self {
            config: config.clone(),
            registry,
            preparation_custody: custody,
            input_retention: None,
            outer_supervisor: None,
        }
    }

    /// Retains original guest inputs through cleanup or conservative quarantine.
    pub(crate) fn with_input_retention(mut self, retention: Arc<dyn Send + Sync>) -> Self {
        self.input_retention = Some(retention);
        self
    }

    /// Borrows one original outer cap for an explicitly bounded operation scope.
    ///
    /// Each admitted Service still receives its own owner and budget roster.
    /// Returning a durable session requires the original unborrowed factory.
    pub(crate) fn with_outer_supervisor(mut self, supervisor: HostOperationSupervisor) -> Self {
        self.outer_supervisor = Some(supervisor);
        self
    }

    /// Reserves an authentication-only Replay Service on the original actor.
    pub(crate) fn start_for_archive_authentication(
        &self,
        scenario: &ScenarioDefForm,
        cancellation: ExecutionCancellation,
    ) -> Result<RetainedTemplateService, PackagedQemuExecutorError> {
        RetainedTemplateService::start(
            self,
            scenario,
            None,
            ServiceHeadroom::FutureAssignment,
            ServicePurpose::Replay,
            cancellation,
        )
    }

    /// Reserves a fresh interactive Replay Service without a campaign row.
    pub(crate) fn start_for_interactive_session(
        &self,
        scenario: &ScenarioDefForm,
        cancellation: ExecutionCancellation,
    ) -> Result<RetainedTemplateService, PackagedQemuExecutorError> {
        RetainedTemplateService::start(
            self,
            scenario,
            None,
            ServiceHeadroom::FutureAssignment,
            ServicePurpose::Replay,
            cancellation,
        )
    }

    pub(crate) fn start(
        &self,
        scenario: &ScenarioDefForm,
        checkpoint: Option<crucible_campaign::ExactCheckpointId>,
    ) -> Result<RetainedTemplateService, PackagedQemuExecutorError> {
        RetainedTemplateService::start(
            self,
            scenario,
            checkpoint,
            ServiceHeadroom::FutureAssignment,
            ServicePurpose::RetainedTemplate,
            ExecutionCancellation::default(),
        )
    }

    /// Admits reproduction of an authenticated durable completed assignment.
    ///
    /// # Errors
    /// Refuses insufficient Service and future-assignment headroom, canceled
    /// admission, or a semantic basis that cannot bind the fresh physical owner.
    pub(crate) fn start_for_completed_reproduction(
        &self,
        basis: &super::super::guarded::CompletedReproductionBasis,
        cancellation: ExecutionCancellation,
    ) -> Result<RetainedTemplateService, PackagedQemuExecutorError> {
        let mut service = RetainedTemplateService::start(
            self,
            basis.source(),
            None,
            ServiceHeadroom::FutureAssignment,
            ServicePurpose::Replay,
            cancellation,
        )?;
        service.context = service
            .context
            .clone()
            .with_completed_reproduction_basis(basis.request(), basis.runtime_basis())?;
        Ok(service)
    }

    /// Consumes an authenticated import into independently admitted receiver authority.
    ///
    /// The returned basis retains the receiver repository through native world
    /// cleanup. No source process-local execution identity is installed.
    ///
    /// # Errors
    /// Refuses insufficient actual Service and assignment headroom, canceled
    /// admission, or watchdog setup. No process is created on failure.
    pub(crate) fn start_for_imported_checkpoint(
        &self,
        imported: crate::imported_checkpoint::AuthenticatedImportedCheckpoint<'_>,
        cancellation: ExecutionCancellation,
    ) -> Result<
        (
            RetainedTemplateService,
            crate::imported_checkpoint::ImportedCheckpointBasis,
        ),
        PackagedQemuExecutorError,
    > {
        if imported.authentication_owner().cancellation().is_canceled()
            || imported
                .authentication_owner()
                .host_ram_resource_ceiling()
                .is_none()
        {
            return Err(HostOperationalError::Unavailable.into());
        }
        let requested = imported.resources();
        let budgets = imported.budgets();
        budgets.validate(false).map_err(|source| {
            PackagedQemuExecutorError::PreparationSupervisor(std::io::Error::other(source))
        })?;
        let ceiling = self
            .config
            .assignment_limits()
            .ok_or(HostOperationalError::Unavailable)?;
        if requested.maximum_vcpus() > ceiling.maximum_vcpus()
            || requested.maximum_resident_bytes() > ceiling.maximum_resident_bytes()
            || requested.maximum_disk_bytes() > ceiling.maximum_disk_bytes()
            || requested.maximum_execution_quanta() > ceiling.maximum_execution_quanta()
        {
            return Err(HostOperationalError::InvalidMessage {
                message: "imported replay exceeds receiver assignment limits".into(),
            }
            .into());
        }
        let mut service = RetainedTemplateService::start(
            self,
            imported.source(),
            Some(imported.checkpoint()),
            ServiceHeadroom::FutureAssignment,
            ServicePurpose::Replay,
            cancellation,
        )?;
        let supervisor = service
            .context
            .host_operation_supervisor()
            .ok_or(HostOperationalError::Unavailable)?;
        supervisor.update_budgets(0, budgets).map_err(|source| {
            PackagedQemuExecutorError::PreparationSupervisor(std::io::Error::other(source))
        })?;
        let (basis, selected) = imported.into_launch().map_err(|source| {
            PackagedQemuExecutorError::PreparationSupervisor(std::io::Error::other(source))
        })?;
        service.context = service
            .context
            .clone()
            .with_service_resources(basis.resources)
            .install_selected_checkpoint(Some(selected));
        Ok((service, basis))
    }

    /// Admits receiver genesis while retaining the authentication owner's cap.
    pub(crate) fn start_for_imported_genesis(
        &self,
        imported: &crate::imported_checkpoint::AuthenticatedImportedCheckpoint<'_>,
        cancellation: ExecutionCancellation,
    ) -> Result<RetainedTemplateService, PackagedQemuExecutorError> {
        let original = imported
            .authentication_owner()
            .host_operation_supervisor()
            .ok_or(HostOperationalError::Unavailable)?;
        let constrained = self.clone().with_outer_supervisor(original.clone());
        RetainedTemplateService::start(
            &constrained,
            imported.source(),
            None,
            ServiceHeadroom::FutureAssignment,
            ServicePurpose::Replay,
            cancellation,
        )
    }

    /// Admits a replay owner after its original physical assignment has ended.
    ///
    /// # Errors
    /// Rejects a mismatched selected root or insufficient actual capacity for
    /// the Service and authored future assignment. Refuses uncertain owner or
    /// watchdog construction; the selected claim remains with the caller.
    pub(crate) fn start_for_replay_basis(
        &self,
        basis: &crate::qemu_baked_genesis::ProductionCheckpointReplayBasis,
        checkpoint: Option<crucible_campaign::ExactCheckpointId>,
        cancellation: ExecutionCancellation,
        selected_root: &mut Option<crate::executor_supervisor::SelectedExactCheckpointRoot>,
    ) -> Result<RetainedTemplateService, PackagedQemuExecutorError> {
        match (checkpoint, selected_root.as_ref()) {
            (Some(checkpoint), Some(root)) if root.authorizes(checkpoint) => {}
            (None, None) => {}
            _ => {
                return Err(HostOperationalError::InvalidMessage {
                    message: "replay source differs from its selected exact root".into(),
                }
                .into());
            }
        }

        let mut service = RetainedTemplateService::start(
            self,
            basis.source(),
            checkpoint,
            ServiceHeadroom::FutureAssignment,
            ServicePurpose::Replay,
            cancellation,
        )?;
        service.context = service
            .context
            .clone()
            .with_semantic_replay_basis(
                basis.resources(),
                basis.runtime_basis(),
                basis.start_mode(),
            )
            .install_selected_checkpoint(selected_root.take());
        Ok(service)
    }

    /// Creates fresh physical authority for an authenticated exact continuation.
    ///
    /// # Errors
    /// Rejects a mismatched selected root, a stale or foreign assignment owner,
    /// or insufficient remaining capacity for the Service. The existing child
    /// must still occupy its complete actor reservation. Failed admission
    /// leaves the selected claim with the caller.
    pub(crate) fn start_for_resume(
        &self,
        scenario: &ScenarioDefForm,
        checkpoint: crucible_campaign::ExactCheckpointId,
        original: &AttemptExecutionContext,
        selected_root: &mut Option<crate::executor_supervisor::SelectedExactCheckpointRoot>,
    ) -> Result<RetainedTemplateService, PackagedQemuExecutorError> {
        if !selected_root
            .as_ref()
            .is_some_and(|root| root.authorizes(checkpoint))
        {
            return Err(HostOperationalError::InvalidMessage {
                message: "selected exact root differs from the requested retained source"
                    .to_owned(),
            }
            .into());
        }

        let Some(crucible_api::host_operational::HostOuterCapOwner::Execution(existing_owner)) =
            original.host_outer_cap_owner()
        else {
            return Err(HostOperationalError::Unavailable.into());
        };
        let daemon = crate::host_operational_registry::operational_identity(
            self.config.daemon_epoch.as_bytes(),
        );
        if original.host_daemon_epoch() != daemon {
            return Err(HostOperationalError::Unavailable.into());
        }
        let mut service = RetainedTemplateService::start(
            self,
            scenario,
            Some(checkpoint),
            ServiceHeadroom::AdmittedAssignment(existing_owner),
            ServicePurpose::RetainedTemplate,
            ExecutionCancellation::default(),
        )?;
        // The selected root and runtime basis describe modeled continuation.
        // The Service's controller, resource owner, and original cap are new.
        service.context = service
            .context
            .clone()
            .with_semantic_resume_basis(original)
            .install_selected_checkpoint(selected_root.take());
        Ok(service)
    }
}

impl RetainedTemplateService {
    fn start(
        factory: &RetainedTemplateServiceFactory,
        scenario: &ScenarioDefForm,
        checkpoint: Option<crucible_campaign::ExactCheckpointId>,
        headroom: ServiceHeadroom,
        purpose: ServicePurpose,
        cancellation: ExecutionCancellation,
    ) -> Result<Self, PackagedQemuExecutorError> {
        let config = &factory.config;
        let service = config
            .retained_template_resources()
            .ok_or(HostOperationalError::Unavailable)?;
        let assignment = config
            .assignment_resources()
            .ok_or(HostOperationalError::Unavailable)?;
        let quanta = config
            .assignment_limits()
            .ok_or(HostOperationalError::Unavailable)?
            .maximum_execution_quanta();
        // The watcher is outside every node partition. Its full stack remains
        // charged even while the source performs no operational work.
        let service_resident = config.host.watcher_service_resident_bytes();
        if service_resident <= crate::supervision::HOST_WATCHDOG_STACK_BYTES as u64 {
            return Err(HostOperationalError::Unavailable.into());
        }
        let node_resident = service
            .resident_peak_bytes
            .checked_sub(service_resident)
            .ok_or(HostOperationalError::Unavailable)?;
        let mut node_ceiling = service;
        node_ceiling.resident_peak_bytes = node_resident;
        node_ceiling.task_slots = node_ceiling
            .task_slots
            .checked_sub(1)
            .filter(|tasks| *tasks > 0)
            .ok_or(HostOperationalError::Unavailable)?;
        let vcpus =
            u32::try_from(service.cpu_slots).map_err(|_| HostOperationalError::Unavailable)?;
        let resources =
            AttemptResourceLimits::new(vcpus, node_resident, service.backing_peak_bytes, quanta)?;
        validate_world_floor(
            &factory.registry,
            scenario,
            resources,
            service,
            service_resident,
        )?;

        let budgets = config
            .host_operation_budgets()
            .ok_or(HostOperationalError::Unavailable)?;
        let incarnation = HostOperationSupervisor::new(budgets, None).map_err(|error| {
            PackagedQemuExecutorError::PreparationSupervisor(std::io::Error::other(error))
        })?;
        let owner_nonce = incarnation.cap_id();
        let supervisor = match &factory.outer_supervisor {
            Some(original) => original.new_budget_owner(budgets).map_err(|error| {
                PackagedQemuExecutorError::PreparationSupervisor(std::io::Error::other(error))
            })?,
            None => incarnation,
        };
        let daemon =
            crate::host_operational_registry::operational_identity(config.daemon_epoch.as_bytes());
        let mut owner_digest = blake3::Hasher::new();
        owner_digest.update(b"crucible.host.retained-template-owner.v1\0");
        owner_digest.update(&daemon);
        owner_digest.update(&owner_nonce);
        let owner = *owner_digest.finalize().as_bytes();
        let registry = factory.registry.clone();
        let _live_capacity_actor = registry.capacity_custody()?;
        match headroom {
            ServiceHeadroom::FutureAssignment => {
                registry.reserve_service_with_assignment_headroom(owner, service, assignment)?;
            }
            ServiceHeadroom::AdmittedAssignment(existing_owner) => {
                registry.reserve_service_with_admitted_assignment(
                    owner,
                    service,
                    existing_owner,
                )?;
            }
        }
        // The actor charges the full service once, while native nodes borrow
        // only the subset that excludes its retained watcher task and memory.
        // Subsequent factory admission reads this immutable subset from the
        // same actor; it cannot reconstruct the complete peak into node RAM.
        if let Err(error) = registry.configure_owner(daemon, owner, node_ceiling) {
            registry.release_service_after_cleanup(owner)?;
            return Err(error.into());
        }

        let watchdog_result = if factory.outer_supervisor.is_some() {
            AssignmentHostWatchdogGuard::start_borrowed_service(supervisor, cancellation.clone())
        } else {
            AssignmentHostWatchdogGuard::start_service(supervisor, cancellation.clone())
        };
        let watchdog = match watchdog_result {
            Ok(watchdog) => watchdog,
            Err(error) => {
                registry.release_service_after_cleanup(owner)?;
                return Err(PackagedQemuExecutorError::PreparationSupervisor(error));
            }
        };
        let context = AttemptExecutionContext::for_preparation_service(
            resources,
            registry.clone(),
            daemon,
            owner,
            watchdog.state.clone(),
            cancellation,
        )
        .and_then(|context| match purpose {
            ServicePurpose::RetainedTemplate => context.with_retained_template_role(),
            ServicePurpose::Replay => Ok(context),
        });
        match context {
            Ok(context) => Ok(Self {
                native_context: context.clone().with_resume_checkpoint(checkpoint),
                context: context.with_resume_checkpoint(checkpoint),
                watchdog: Mutex::new(Some(watchdog)),
                registry,
                owner,
                released: AtomicBool::new(false),
                preparation_custody: Arc::clone(&factory.preparation_custody),
                _input_retention: factory.input_retention.clone(),
            }),
            Err(error) => {
                let mut watchdog = watchdog;
                watchdog.stop();
                registry.release_service_after_cleanup(owner)?;
                Err(error.into())
            }
        }
    }

    /// Binds a finding root to the original authentication Service.
    ///
    /// Selection and native restoration retain the same admitted owner and
    /// original cap. The controller's linear claim moves only after validation.
    ///
    /// # Errors
    /// Refuses an absent or substituted root, a released Service, or a Service
    /// already bound to a checkpoint. Refusal preserves the caller's claim and
    /// both existing contexts.
    pub(crate) fn bind_authenticated_finding_debug(
        &mut self,
        checkpoint: crucible_campaign::ExactCheckpointId,
        selected: &mut Option<crate::executor_supervisor::SelectedExactCheckpointRoot>,
    ) -> Result<(), PackagedQemuExecutorError> {
        if self.released.load(Ordering::Acquire)
            || self.context.resume_checkpoint().is_some()
            || self.native_context.resume_checkpoint().is_some()
            || !selected
                .as_ref()
                .is_some_and(|root| root.authorizes(checkpoint))
        {
            return Err(HostOperationalError::Unavailable.into());
        }

        self.native_context = self
            .native_context
            .clone()
            .with_resume_checkpoint(Some(checkpoint));
        self.context = self
            .context
            .clone()
            .with_resume_checkpoint(Some(checkpoint))
            .install_selected_checkpoint(selected.take());
        Ok(())
    }

    pub(crate) fn context(&self) -> &AttemptExecutionContext {
        &self.context
    }

    /// Returns the admitted physical process limits before semantic projection.
    ///
    /// This context shares the Service's cap and cancellation. Selected exact
    /// root authority remains linear in the semantic restore context.
    pub(crate) fn native_context(&self) -> &AttemptExecutionContext {
        &self.native_context
    }

    pub(super) fn is_released(&self) -> bool {
        self.released.load(Ordering::Acquire)
    }

    /// Retains an owner whose native cleanup cannot yet be proven.
    ///
    /// A failed native launch may own a cgroup or quota before node admission.
    /// An empty node ledger therefore cannot authorize discharge here. The
    /// complete observer and original charged actor remain in quarantine for
    /// the process lifetime, independent of ordinary cleanup-on-drop behavior.
    pub(crate) fn retain_after_unknown_cleanup(self) {
        let custody = self
            .registry
            .capacity_custody()
            .unwrap_or_else(|_| Arc::clone(&self.preparation_custody));
        let _quarantined_for_process_lifetime = Box::leak(Box::new((custody, self)));
    }

    /// Releases only after the caller proves physical source-world cleanup.
    pub(crate) fn release_after_world_cleanup(&self) -> Result<(), HostOperationalError> {
        let mut guard = self
            .watchdog
            .lock()
            .map_err(|_| HostOperationalError::Unavailable)?;
        if self.released.load(Ordering::Acquire) {
            return Ok(());
        }
        if !self.registry.service_nodes_cleaned(self.owner)? {
            return Err(HostOperationalError::Unavailable);
        }
        if let Some(mut watchdog) = guard.take() {
            // Joining precedes the actor discharge; an idle watchdog is still
            // a real task with an independently charged resident stack.
            watchdog.stop();
        }
        self.registry.release_service_after_cleanup(self.owner)?;
        self.released.store(true, Ordering::Release);
        Ok(())
    }
}

fn validate_world_floor(
    registry: &crate::HostOperationalRegistry,
    scenario: &ScenarioDefForm,
    resources: AttemptResourceLimits,
    service: HostResourceVector,
    service_resident: u64,
) -> Result<(), PackagedQemuExecutorError> {
    let bootstrap = registry
        .bootstrap_limits()
        .ok_or(HostOperationalError::Unavailable)?;
    let shapes = scenario
        .world()
        .vm_nodes()
        .iter()
        .map(|node| {
            Ok(crucible_api::vm_lifecycle::ProductionHostRamLaunchShape {
                node: node.id.name.clone(),
                declared_ram_bytes: u64::from(node.memory_mib)
                    .checked_mul(1024 * 1024)
                    .ok_or(HostOperationalError::Unavailable)?,
                vcpus: u32::from(node.smp_vcpus),
            })
        })
        .collect::<Result<Vec<_>, HostOperationalError>>()?;
    let requirements = crate::qemu_campaign_lifecycle::host_ram_launch_requirements(&shapes)?;
    let partition = crucible_api::vm_lifecycle::partition_host_ram_launch_resources(
        &shapes,
        resources,
        bootstrap,
        &requirements,
    )?;
    let mut floor = partition.ceiling;
    floor.task_slots = floor
        .task_slots
        .checked_add(1)
        .ok_or(HostOperationalError::Unavailable)?;
    floor.resident_peak_bytes = floor
        .resident_peak_bytes
        .checked_add(service_resident)
        .ok_or(HostOperationalError::Unavailable)?;
    if floor.resident_peak_bytes > service.resident_peak_bytes
        || floor.backing_peak_bytes > service.backing_peak_bytes
        || floor.metadata_bytes > service.metadata_bytes
        || floor.staging_bytes > service.staging_bytes
        || floor.paging_io_slots > service.paging_io_slots
        || floor.cpu_slots > service.cpu_slots
        || floor.task_slots > service.task_slots
        || floor.file_descriptors > service.file_descriptors
    {
        return Err(HostOperationalError::Unavailable.into());
    }
    Ok(())
}

impl Drop for RetainedTemplateService {
    fn drop(&mut self) {
        if self.release_after_world_cleanup().is_ok() {
            return;
        }
        // Unproven retirement keeps its independent service observer alive.
        // The actor retains the complete charge until actual node cleanup;
        // dropping a failed builder is not a physical resource discharge.
        let custody = self
            .registry
            .capacity_custody()
            .unwrap_or_else(|_| Arc::clone(&self.preparation_custody));
        // The observer may already be joined when the actor refuses its final
        // discharge. Preserve capacity custody in that case too, and preserve
        // a poisoned observer mutex without destroying its live worker.
        let watchdog = std::mem::replace(&mut self.watchdog, Mutex::new(None));
        // Materialized guest files remain necessary while any native cleanup
        // is uncertain, including the ordinary Drop failure path.
        let input_retention = self._input_retention.take();
        let _quarantined_for_process_lifetime =
            Box::leak(Box::new((custody, watchdog, input_retention)));
    }
}

impl crucible_api::vm_lifecycle::ProductionHotForkCleanupObserver for RetainedTemplateService {
    fn after_world_cleanup(&self) -> Result<(), HostOperationalError> {
        self.release_after_world_cleanup()
    }
}
