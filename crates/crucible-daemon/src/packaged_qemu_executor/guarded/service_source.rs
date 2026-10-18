//! Selects the same preborn Source role before guarded Service operations.
//!
//! Every operation projects the actual Main-held phase. This helper neither
//! extracts a Service nor reserves a second World while handing it to callers.

use super::*;
use crate::ProductionVmLifecycleConfig;
use crate::lifecycle_cleanup::{PreparedSourceFailure, ServiceMainHandle, ServiceMainReceiver};
use crate::qemu_campaign_lifecycle::QemuAttemptProductionVmLifecycleError;

pub(crate) type GuardedServiceLifecycleFactory = QemuAttemptProductionVmLifecycleFactory<
    ComposedQemuAttemptResourceGuardFactory<
        SharedQemuAttemptHostResourceFactory<LinuxQemuAttemptHostResourceFactory>,
    >,
>;

/// Retains the launch facade and its same admitted Service selection together.
///
/// The original Main owns the Pending allocation and partial Service. Dropping
/// this facade cannot destroy those bodies or release their role.
pub(crate) struct GuardedServiceSource {
    pub(crate) factory: GuardedServiceLifecycleFactory,
    service: ServiceMainHandle,
}

impl GuardedCampaignOwner {
    /// Prepares the actual lifecycle provider before its first Service effect.
    pub(crate) fn prepare_service_source(
        &self,
        lifecycle: Arc<ProductionVmLifecycleConfig>,
    ) -> Result<GuardedServiceSource, QemuAttemptProductionVmLifecycleError> {
        let mut factory = QemuAttemptProductionVmLifecycleFactory::new(
            lifecycle,
            ComposedQemuAttemptResourceGuardFactory::new(self.inner.host.clone()),
        );
        let service = factory.prepare_source_construction()?;
        Ok(GuardedServiceSource { factory, service })
    }
}

impl GuardedCampaignOwner {
    /// Installs actual imported input before any receiver preflight can refuse.
    pub(crate) fn prepare_imported_service_source(
        &self,
        capsule: crate::imported_checkpoint::RetainedImportedCheckpoint,
    ) -> Result<GuardedServiceSource, crate::ImportedSourcePreparationFailure> {
        let mut factory = QemuAttemptProductionVmLifecycleFactory::new(
            self.inner.config.lifecycle.clone(),
            ComposedQemuAttemptResourceGuardFactory::new(self.inner.host.clone()),
        );
        let service = factory.prepare_source_construction_with_import(capsule)?;
        Ok(GuardedServiceSource { factory, service })
    }
}

impl GuardedServiceSource {
    /// Runs one startup projection while the actual owner retains every cause.
    ///
    /// The returned output is taken only after the startup driver's postcut.
    /// This wrapper performs no later fallible check that could discard it.
    pub(crate) fn start<T>(
        &self,
        phase: &'static str,
        start: impl FnOnce(&mut RetainedServiceStart) -> Result<T, RetainedServiceStartRefusal>,
    ) -> Result<T, PreparedSourceFailure> {
        match self.service.with_start(start) {
            Ok(Ok(output)) => Ok(output),
            Ok(Err(_report)) => Err(self.failure(phase)),
            Err(first) => Err(self.service.failure_with_refusal(phase, first)),
        }
    }

    /// Registers the actual external alias receiver before producing any alias.
    pub(crate) fn retain_receiver(
        &self,
        phase: &'static str,
    ) -> Result<ServiceMainReceiver, PreparedSourceFailure> {
        self.service
            .retain_receiver()
            .map_err(|first| self.service.failure_with_refusal(phase, first))
    }

    /// Borrows the actual ready owner without extracting Service custody.
    ///
    /// The caller first retains its real receiver, keeps any resulting owned
    /// aliases within that body and explicitly returns it after destruction.
    pub(crate) fn with_ready<T>(
        &self,
        phase: &'static str,
        project: impl FnOnce(&RetainedTemplateService) -> T,
    ) -> Result<T, PreparedSourceFailure> {
        self.service
            .with_ready(project)
            .map_err(|first| self.service.failure_with_refusal(phase, first))
    }

    /// Keeps the actual external Original leaf outside a refused projection.
    pub(crate) fn supervision_failure(
        &self,
        phase: &'static str,
        first: crucible_linux_resource::host_supervision::HostSupervisionError,
    ) -> GuardedServiceSupervisionFailure {
        // This leaf is Copy and has no owning debt. Retain the outer copy even
        // when the projection cannot enter or its existing first is occupied.
        let custody = match self
            .service
            .with_start(|start| start.record_external_supervision(first))
        {
            Ok(()) => self.failure(phase),
            Err(access) => self.service.failure_with_refusal(phase, access),
        };
        GuardedServiceSupervisionFailure { first, custody }
    }

    /// Retains an owning admission cause until the actual Main accepts it.
    pub(crate) fn admission_failure(
        &self,
        phase: &'static str,
        first: crucible_api::host_operational::HostOperationalError,
    ) -> GuardedServiceAdmissionFailure {
        let mut first = Some(first);
        let projected = self.service.with_start(|start| {
            if start.first().is_none()
                && let Some(first) = first.take()
            {
                start.record_initial_failure(first);
            }
        });
        let custody = match projected {
            Ok(()) => self.failure(phase),
            Err(access) => self.service.failure_with_refusal(phase, access),
        };
        GuardedServiceAdmissionFailure {
            first: first.map(PackagedQemuExecutorError::HostOperational),
            custody,
        }
    }

    pub(crate) fn service_handle(&self) -> ServiceMainHandle {
        self.service.prepared_selector().service_main_handle()
    }

    pub(crate) fn failure(&self, phase: &'static str) -> PreparedSourceFailure {
        match self.factory.prepared_source_handle() {
            Ok(prepared) => prepared.failure(phase),
            // This is a pure selector lookup. Its actual absent-role refusal
            // still travels through the same Service role, without a new bank.
            Err(first) => self.service.failure_with_refusal(phase, first),
        }
    }
}

/// Keeps an uninstalled raw admission cause beside the same-role report.
#[derive(Debug)]
pub(crate) struct GuardedServiceAdmissionFailure {
    first: Option<PackagedQemuExecutorError>,
    custody: PreparedSourceFailure,
}

impl GuardedServiceAdmissionFailure {
    pub(crate) fn into_parts(self) -> (Option<PackagedQemuExecutorError>, PreparedSourceFailure) {
        (self.first, self.custody)
    }
}

impl std::fmt::Display for GuardedServiceAdmissionFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.first {
            Some(first) => std::fmt::Display::fmt(first, formatter),
            None => std::fmt::Display::fmt(&self.custody, formatter),
        }
    }
}

impl std::error::Error for GuardedServiceAdmissionFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.first {
            Some(first) => Some(first),
            None => Some(&self.custody),
        }
    }
}

/// Keeps the Copy caller refusal independently of Main projection access.
#[derive(Debug, thiserror::Error)]
#[error("Service caller Original refused: {first}; retained custody: {custody}")]
pub(crate) struct GuardedServiceSupervisionFailure {
    #[source]
    first: crucible_linux_resource::host_supervision::HostSupervisionError,
    custody: PreparedSourceFailure,
}

impl GuardedServiceSupervisionFailure {
    /// Moves both actual initiating Original and independent Main access facts.
    pub(crate) fn into_parts(
        self,
    ) -> (
        crucible_linux_resource::host_supervision::HostSupervisionError,
        PreparedSourceFailure,
    ) {
        (self.first, self.custody)
    }
}

/// Scopes one authentication context under its original Main transport receiver.
///
/// The owning phase retains its actual Original; this facade holds only the
/// known local context alias and acknowledges it after that alias is destroyed.
pub(crate) struct GuardedAuthenticationSource {
    source: GuardedServiceSource,
    context: Option<AttemptExecutionContext>,
    receiver: Option<crate::lifecycle_cleanup::ServiceMainReceiverHandle>,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum GuardedAuthenticationError {
    #[error("prepare authentication Source: {0}")]
    Factory(#[source] QemuAttemptProductionVmLifecycleError),
    #[error("authentication Source refused: {0}")]
    Prepared(#[source] PreparedSourceFailure),
    #[error("authentication Service admission failed: {0}")]
    Admission(#[source] GuardedServiceAdmissionFailure),
}

impl GuardedCampaignOwner {
    pub(crate) fn prepare_authentication_source(
        &self,
        scenario: &ScenarioDefForm,
        cancellation: ExecutionCancellation,
        class: crucible_linux_resource::host_supervision::HostOperationClass,
    ) -> Result<GuardedAuthenticationSource, GuardedAuthenticationError> {
        let source = self
            .prepare_service_source(self.inner.config.lifecycle.clone())
            .map_err(GuardedAuthenticationError::Factory)?;
        let services = self.replay_services().map_err(|first| {
            GuardedAuthenticationError::Admission(
                source.admission_failure("select authentication Service", first),
            )
        })?;
        source
            .start("start authentication Service", |start| {
                services.start_for_archive_authentication(start, scenario, cancellation)?;
                start.begin_authentication_original(class)
            })
            .map_err(GuardedAuthenticationError::Prepared)?;
        let receiver = source.service.retain_receiver_in_main().map_err(|first| {
            GuardedAuthenticationError::Prepared(
                source
                    .service
                    .failure_with_refusal("retain authentication context", first),
            )
        })?;
        let context = match source.with_ready("borrow authentication context", |service| {
            service.context().clone()
        }) {
            Ok(context) => context,
            Err(first) => {
                let _returned = receiver.return_after_alias_destruction();
                return Err(GuardedAuthenticationError::Prepared(first));
            }
        };
        Ok(GuardedAuthenticationSource {
            source,
            context: Some(context),
            receiver: Some(receiver),
        })
    }
}

impl GuardedAuthenticationSource {
    pub(crate) fn context(&self) -> Result<&AttemptExecutionContext, GuardedAuthenticationError> {
        self.context.as_ref().ok_or_else(|| {
            GuardedAuthenticationError::Prepared(
                self.source.failure("authentication context was consumed"),
            )
        })
    }

    pub(crate) fn check(&self) -> Result<(), GuardedAuthenticationError> {
        self.source
            .start("check retained authentication Original", |start| {
                start.check_authentication_original()
            })
            .map_err(GuardedAuthenticationError::Prepared)
    }

    pub(crate) fn complete(&self) -> Result<(), GuardedAuthenticationError> {
        self.source
            .start("complete retained authentication Original", |start| {
                start.complete_authentication_original()
            })
            .map_err(GuardedAuthenticationError::Prepared)
    }
}

impl Drop for GuardedAuthenticationSource {
    fn drop(&mut self) {
        drop(self.context.take());
        if let Some(receiver) = self.receiver.take()
            && let Err(first) = receiver.return_after_alias_destruction()
        {
            let _retained = self
                .source
                .service
                .failure_with_refusal("return authentication context", first);
        }
        // A genuine child lease may keep this parent pending. Never wait for
        // parent finality while exposing that independently retained child.
        let _retained = self.source.failure("retire authentication Source");
    }
}
