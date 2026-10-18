//! Independently charged owners for the physical lifetime of retained worlds.
//!
//! Every startup projection writes into the caller's same Main-prepaid phase.
//! Successful Service ownership stays there through World admission and cleanup;
//! startup refusal returns only a report while its actual cause remains owned.

mod retirement_input;
mod startup;
pub(crate) use retirement_input::ServiceRetirementInput;
pub(crate) use startup::{RetainedServiceStart, RetainedServiceStartRefusal};

use super::*;
use crate::supervision::AssignmentHostWatchdogGuard;
use crucible_api::host_operational::{HostOperationalError, HostResourceVector};
use crucible_campaign::{AttemptResourceLimits, DaemonEpoch};
use crucible_linux_resource::host_supervision::HostOperationSupervisor;
use std::sync::Mutex;

/// Keeps the source's resource reservation and idle-safe supervision alive.
pub(crate) struct RetainedTemplateService {
    context: AttemptExecutionContext,
    native_context: AttemptExecutionContext,
    watchdog: Mutex<Option<AssignmentHostWatchdogGuard>>,
    watchdog_stop: Mutex<Option<crate::supervision::ServiceWatchdogStop>>,
    registry: crate::HostOperationalRegistry,
    owner: [u8; 32],
    preparation_custody: Arc<dyn Send + Sync>,
    _input_retention: Option<Arc<dyn Send + Sync>>,
    _capacity_custody: Arc<dyn Send + Sync>,
}

#[derive(Clone)]
pub(crate) struct RetainedTemplateServiceFactory {
    policy: RetainedTemplateServicePolicy,
    registry: crate::HostOperationalRegistry,
    preparation_custody: Arc<dyn Send + Sync>,
    input_retention: Option<Arc<dyn Send + Sync>>,
    outer_supervisor: Option<HostOperationSupervisor>,
}

/// Copies only the immutable values used by Service admission.
///
/// Missing options remain absent until admission performs its existing checks.
#[derive(Clone, Copy)]
struct RetainedTemplateServicePolicy {
    daemon_epoch: DaemonEpoch,
    retained_template_resources: Option<HostResourceVector>,
    assignment_resources: Option<HostResourceVector>,
    assignment_limits: Option<AttemptResourceLimits>,
    host_operation_budgets: Option<crucible_api::host_operational::HostOperationBudgets>,
    watcher_service_resident_bytes: u64,
}

impl RetainedTemplateServicePolicy {
    fn from_config(config: &PackagedQemuExecutorConfig) -> Self {
        Self {
            daemon_epoch: config.daemon_epoch,
            retained_template_resources: config.retained_template_resources(),
            assignment_resources: config.assignment_resources(),
            assignment_limits: config.assignment_limits(),
            host_operation_budgets: config.host_operation_budgets(),
            watcher_service_resident_bytes: config.host.watcher_service_resident_bytes(),
        }
    }
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
        startup: &mut RetainedServiceStart,
        scenario: &ScenarioDefForm,
        original: &AttemptExecutionContext,
    ) -> Result<(), RetainedServiceStartRefusal> {
        self.start_comparison_for_test(startup, scenario, original, true)
    }

    /// Charges an independent comparison child under the live accepted owner.
    ///
    /// This receipt authorizes a physical comparison Service; it does not
    /// manufacture another campaign assignment or another selected root.
    #[cfg(test)]
    pub(in crate::packaged_qemu_executor) fn start_comparison_child_for_test(
        &self,
        startup: &mut RetainedServiceStart,
        scenario: &ScenarioDefForm,
        original: &AttemptExecutionContext,
    ) -> Result<(), RetainedServiceStartRefusal> {
        self.start_comparison_for_test(startup, scenario, original, false)
    }

    #[cfg(test)]
    fn start_comparison_for_test(
        &self,
        startup: &mut RetainedServiceStart,
        scenario: &ScenarioDefForm,
        original: &AttemptExecutionContext,
        causal_source: bool,
    ) -> Result<(), RetainedServiceStartRefusal> {
        startup.run(|startup| {
            let Some(crucible_api::host_operational::HostOuterCapOwner::Execution(owner)) =
                original.host_outer_cap_owner()
            else {
                return Err(HostOperationalError::Unavailable.into());
            };
            if original.host_daemon_epoch()
                != crate::host_operational_registry::operational_identity(
                    self.policy.daemon_epoch.as_bytes(),
                )
            {
                return Err(HostOperationalError::Unavailable.into());
            }

            startup.start(
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
            let service = startup.ready_mut()?;
            service.context = service.context.clone().with_semantic_resume_basis(original);
            if causal_source {
                service.context = service.context.clone().with_resume_checkpoint(None);
            }
            Ok(())
        })
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
            policy: RetainedTemplateServicePolicy::from_config(config),
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
        startup: &mut RetainedServiceStart,
        scenario: &ScenarioDefForm,
        cancellation: ExecutionCancellation,
    ) -> Result<(), RetainedServiceStartRefusal> {
        startup.run(|startup| {
            startup.start(
                self,
                scenario,
                None,
                ServiceHeadroom::FutureAssignment,
                ServicePurpose::Replay,
                cancellation,
            )
        })
    }

    /// Reserves a fresh interactive Replay Service without a campaign row.
    pub(crate) fn start_for_interactive_session(
        &self,
        startup: &mut RetainedServiceStart,
        scenario: &ScenarioDefForm,
        cancellation: ExecutionCancellation,
    ) -> Result<(), RetainedServiceStartRefusal> {
        startup.run(|startup| {
            startup.start(
                self,
                scenario,
                None,
                ServiceHeadroom::FutureAssignment,
                ServicePurpose::Replay,
                cancellation,
            )
        })
    }

    pub(crate) fn start(
        &self,
        startup: &mut RetainedServiceStart,
        scenario: &ScenarioDefForm,
        checkpoint: Option<crucible_campaign::ExactCheckpointId>,
    ) -> Result<(), RetainedServiceStartRefusal> {
        startup.run(|startup| {
            startup.start(
                self,
                scenario,
                checkpoint,
                ServiceHeadroom::FutureAssignment,
                ServicePurpose::RetainedTemplate,
                ExecutionCancellation::default(),
            )
        })
    }

    /// Admits reproduction of an authenticated durable completed assignment.
    ///
    /// # Errors
    /// Refuses insufficient Service and future-assignment headroom, canceled
    /// admission, or a semantic basis that cannot bind the fresh physical owner.
    pub(crate) fn start_for_completed_reproduction(
        &self,
        startup: &mut RetainedServiceStart,
        basis: &super::super::guarded::CompletedReproductionBasis,
        cancellation: ExecutionCancellation,
    ) -> Result<(), RetainedServiceStartRefusal> {
        startup.run(|startup| {
            startup.start(
                self,
                basis.source(),
                None,
                ServiceHeadroom::FutureAssignment,
                ServicePurpose::Replay,
                cancellation,
            )?;
            let service = startup.ready_mut()?;
            service.context = service
                .context
                .clone()
                .with_completed_reproduction_basis(basis.request(), basis.runtime_basis())?;
            Ok(())
        })
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
        startup: &mut RetainedServiceStart,
        cancellation: ExecutionCancellation,
    ) -> Result<(), RetainedServiceStartRefusal> {
        startup.run(|startup| startup.start_imported(self, cancellation, false))
    }

    /// Keeps the actual authentication Original through every startup refusal.
    pub(crate) fn start_for_maintenance_import(
        &self,
        startup: &mut RetainedServiceStart,
        cancellation: ExecutionCancellation,
    ) -> Result<(), RetainedServiceStartRefusal> {
        startup.run(|startup| startup.start_imported(self, cancellation, true))
    }

    /// Admits independent genesis without consuming the Main-held import.
    pub(crate) fn start_for_imported_genesis(
        &self,
        startup: &mut RetainedServiceStart,
        cancellation: ExecutionCancellation,
    ) -> Result<(), RetainedServiceStartRefusal> {
        startup.run(|startup| startup.start_imported_genesis(self, cancellation))
    }

    /// Admits a replay owner after its original physical assignment has ended.
    ///
    /// The actual selected root, when required, is already in the Main-held
    /// startup phase. No caller-local claim spans Service effects.
    ///
    /// # Errors
    /// Rejects a mismatched selected root or insufficient actual capacity for
    /// the Service and authored future assignment. Refuses uncertain owner or
    /// watchdog construction; Main retains the same pending claim on refusal.
    pub(crate) fn start_for_replay_basis(
        &self,
        startup: &mut RetainedServiceStart,
        basis: &crate::qemu_baked_genesis::ProductionCheckpointReplayBasis,
        checkpoint: Option<crucible_campaign::ExactCheckpointId>,
        cancellation: ExecutionCancellation,
    ) -> Result<(), RetainedServiceStartRefusal> {
        startup.run(|startup| {
            startup.validate_pending_replay_root(checkpoint)?;
            startup.start(
                self,
                basis.source(),
                checkpoint,
                ServiceHeadroom::FutureAssignment,
                ServicePurpose::Replay,
                cancellation,
            )?;
            startup.bind_pending_replay_basis(basis)
        })
    }

    /// Creates fresh physical authority for an authenticated exact continuation.
    ///
    /// # Errors
    /// Rejects a mismatched selected root, a stale or foreign assignment owner,
    /// or insufficient remaining capacity for the Service. Validation refusals
    /// preserve the original selection slot. Once transferred, the same root
    /// stays in Main through Ready handoff or proof-gated startup cleanup.
    pub(crate) fn start_for_resume(
        &self,
        startup: &mut RetainedServiceStart,
        scenario: &ScenarioDefForm,
        checkpoint: crucible_campaign::ExactCheckpointId,
        original: &AttemptExecutionContext,
    ) -> Result<(), RetainedServiceStartRefusal> {
        startup.run(|startup| {
            let Some(crucible_api::host_operational::HostOuterCapOwner::Execution(existing_owner)) =
                original.host_outer_cap_owner()
            else {
                return Err(HostOperationalError::Unavailable.into());
            };
            let daemon = crate::host_operational_registry::operational_identity(
                self.policy.daemon_epoch.as_bytes(),
            );
            if original.host_daemon_epoch() != daemon {
                return Err(HostOperationalError::Unavailable.into());
            }
            startup.retain_resume_root(original, checkpoint)?;
            startup.start(
                self,
                scenario,
                Some(checkpoint),
                ServiceHeadroom::AdmittedAssignment(existing_owner),
                ServicePurpose::RetainedTemplate,
                ExecutionCancellation::default(),
            )?;
            startup.bind_pending_resume_basis(original)
        })
    }
}

impl RetainedTemplateService {
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
    ) -> Result<(), HostOperationalError> {
        if self.context.resume_checkpoint().is_some()
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
}

fn validate_world_floor(
    registry: &crate::HostOperationalRegistry,
    scenario: &ScenarioDefForm,
    resources: AttemptResourceLimits,
    service: HostResourceVector,
    service_resident: u64,
) -> Result<(), startup::RetainedServiceAdmissionError> {
    let bootstrap = registry
        .bootstrap_limits()
        .ok_or(HostOperationalError::Unavailable)?;
    let shapes = scenario
        .world()
        .vm_nodes()
        .iter()
        .map(|node| {
            Ok(
                crucible_api::host_operational::ProductionHostRamLaunchShape {
                    node: node.id.name.clone(),
                    declared_ram_bytes: u64::from(node.memory_mib)
                        .checked_mul(1024 * 1024)
                        .ok_or(HostOperationalError::Unavailable)?,
                    vcpus: u32::from(node.smp_vcpus),
                },
            )
        })
        .collect::<Result<Vec<_>, HostOperationalError>>()?;
    let requirements = crate::qemu_campaign_lifecycle::host_ram_launch_requirements(&shapes)?;
    let partition = crucible_api::host_operational::partition_host_ram_launch_resources(
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
