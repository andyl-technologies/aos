//! Operation-only custody for the actual actor-backed Service algorithm.
//!
//! This component holds the phase on its own stack, never installs a Main key,
//! and exposes no Source, native World, process or physical-return producer.
//! It reuses the same Service effects, Original post/completion and cleanup.

use super::*;

/// Retains actual Service controls in a component that cannot create a World.
pub(in crate::packaged_qemu_executor) struct ComponentServiceCustody {
    startup: RetainedServiceStart,
    quarantine_actor: bool,
}

/// Keeps the same partial phase and raw startup/cleanup history on refusal.
pub(in crate::packaged_qemu_executor) struct ComponentServiceFailure {
    owner: ComponentServiceCustody,
}

#[derive(Debug)]
pub(in crate::packaged_qemu_executor) struct ComponentServiceCleanupRefusal;

impl ComponentServiceCustody {
    fn start(
        factory: &RetainedTemplateServiceFactory,
        scenario: &ScenarioDefForm,
        checkpoint: Option<crucible_campaign::ExactCheckpointId>,
        purpose: ServicePurpose,
        cancellation: ExecutionCancellation,
    ) -> Result<Self, ComponentServiceFailure> {
        // This is test-owned inline storage, not a fabricated Main selection.
        let mut owner = Self {
            startup: RetainedServiceStart::empty_unbound(),
            quarantine_actor: false,
        };
        let result = owner.startup.run_admission(|startup| {
            RetainedServiceStart::start_fields(
                &mut startup.attempted,
                &mut startup.phase,
                &mut startup.admission,
                ServiceContextBinding::ComponentNoNative,
                factory,
                scenario,
                checkpoint,
                ServiceHeadroom::FutureAssignment,
                purpose,
                cancellation,
            )
        });
        match result {
            Ok(()) => Ok(owner),
            Err(_) => {
                // No native entrypoint exists on this owner. The common lower
                // driver disposes only the Service controls actually created.
                let _closed =
                    owner
                        .startup
                        .retry_cleanup(ServiceCleanupBoundary::ComponentNoNative {
                            release_actor: true,
                        });
                Err(ComponentServiceFailure { owner })
            }
        }
    }

    pub(in crate::packaged_qemu_executor) fn context(&self) -> &AttemptExecutionContext {
        self.service().context()
    }

    pub(in crate::packaged_qemu_executor) fn native_context(&self) -> &AttemptExecutionContext {
        self.service().native_context()
    }

    fn service(&self) -> &RetainedTemplateService {
        match self.startup.ready() {
            Some(service) => service,
            None => panic!("component Service projection requires successful startup"),
        }
    }

    /// Scopes semantic finding-binding assertions over the same actual context.
    pub(in crate::packaged_qemu_executor) fn with_service_mut<R>(
        &mut self,
        apply: impl FnOnce(&mut RetainedTemplateService) -> R,
    ) -> R {
        match &mut self.startup.phase {
            ServiceStartPhase::Ready(service) => apply(service),
            _ => panic!("component Service mutation requires successful startup"),
        }
    }

    /// Uses actual node-ledger checks without creating a World-return fact.
    pub(in crate::packaged_qemu_executor) fn cleanup_after_component_borrowers(
        &mut self,
    ) -> Result<(), ComponentServiceCleanupRefusal> {
        self.startup
            .retry_cleanup(ServiceCleanupBoundary::ComponentNoNative {
                release_actor: !self.quarantine_actor,
            });
        if self.startup.is_released() {
            Ok(())
        } else {
            Err(ComponentServiceCleanupRefusal)
        }
    }

    /// Borrows the actual first cleanup refusal after any later physical success.
    pub(in crate::packaged_qemu_executor) fn cleanup_failure(
        &self,
    ) -> Option<&HostOperationalError> {
        self.startup.cleanup_failure()
    }

    /// Preserves the actual actor debit while disposing only known local controls.
    ///
    /// This negative component observation does not assert process cleanup or
    /// retain a model native borrower. The registry's original row stays charged.
    pub(in crate::packaged_qemu_executor) fn retain_after_unknown_cleanup(mut self) {
        self.quarantine_actor = true;
    }
}

impl Drop for ComponentServiceCustody {
    fn drop(&mut self) {
        // The component never handed a context to a native launch. Real node
        // ledger debt still refuses the same common actor-release operation.
        let _closed = self
            .startup
            .retry_cleanup(ServiceCleanupBoundary::ComponentNoNative {
                release_actor: !self.quarantine_actor,
            });
    }
}

impl ComponentServiceFailure {
    pub(in crate::packaged_qemu_executor) fn operational_failure(
        &self,
    ) -> Option<&HostOperationalError> {
        match self.owner.startup.first() {
            Some(RetainedServiceStartCause::Admission(
                RetainedServiceAdmissionError::HostOperational(first),
            )) => Some(first),
            _ => None,
        }
    }
}

impl std::fmt::Debug for ComponentServiceCustody {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        output
            .debug_struct("ComponentServiceCustody")
            .field("first", &self.startup.first())
            .field("cleanup", &self.startup.cleanup_failure())
            .field("released", &self.startup.is_released())
            .field("quarantine_actor", &self.quarantine_actor)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for ComponentServiceFailure {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&self.owner, output)
    }
}

impl std::fmt::Display for ComponentServiceFailure {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.owner.startup.first() {
            Some(first) => std::fmt::Display::fmt(first, output),
            None => output.write_str("component Service startup refused"),
        }
    }
}

impl std::error::Error for ComponentServiceFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.owner
            .startup
            .first()
            .map(|first| first as &dyn std::error::Error)
    }
}

impl RetainedTemplateServiceFactory {
    /// Runs the common Replay Service operations without a native caller.
    pub(in crate::packaged_qemu_executor) fn start_component_replay(
        &self,
        scenario: &ScenarioDefForm,
        cancellation: ExecutionCancellation,
    ) -> Result<ComponentServiceCustody, ComponentServiceFailure> {
        ComponentServiceCustody::start(self, scenario, None, ServicePurpose::Replay, cancellation)
    }

    /// Runs the common retained-template operations without a native caller.
    pub(in crate::packaged_qemu_executor) fn start_component_template(
        &self,
        scenario: &ScenarioDefForm,
        checkpoint: Option<crucible_campaign::ExactCheckpointId>,
    ) -> Result<ComponentServiceCustody, ComponentServiceFailure> {
        ComponentServiceCustody::start(
            self,
            scenario,
            checkpoint,
            ServicePurpose::RetainedTemplate,
            ExecutionCancellation::default(),
        )
    }
}
