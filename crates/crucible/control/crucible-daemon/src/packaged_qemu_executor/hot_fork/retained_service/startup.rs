//! Retains Service startup in the same Main-paid Source constructor phase.
//!
//! The lifecycle factory creates this inline phase before the first Service
//! effect. It moves with that original cell; a report, empty node ledger or
//! missing World callback never supplies physical-return authority.

use super::*;
use crate::supervision::ServiceWatchdogStop;
use thiserror::Error;

mod authentication;
#[cfg(test)]
mod component;
mod imported_genesis;

/// Selects only the context binding after actual actor-backed Service admission.
enum ServiceContextBinding<'a> {
    Main(Option<&'a crate::lifecycle_cleanup::ServiceMainPreclaim>),
    /// This component owns no native/World entrypoint or Main selection.
    #[cfg(test)]
    ComponentNoNative,
}

impl ServiceContextBinding<'_> {
    fn stamp(self, context: &mut AttemptExecutionContext) -> Result<(), HostOperationalError> {
        match self {
            Self::Main(preclaim) => {
                let preclaim = preclaim.ok_or(HostOperationalError::Unavailable)?;
                context.stamp_service_main_selector(preclaim.handle().prepared_selector());
            }
            #[cfg(test)]
            Self::ComponentNoNative => {}
        }
        Ok(())
    }
}

/// Keeps genuine producer return cuts distinct from operation-only test custody.
enum ServiceCleanupBoundary {
    Main {
        world_returned: bool,
    },
    #[cfg(test)]
    ComponentNoNative {
        release_actor: bool,
    },
}

impl ServiceCleanupBoundary {
    fn world_returned(&self) -> bool {
        matches!(
            self,
            Self::Main {
                world_returned: true
            }
        )
    }

    fn allows_empty_component(&self) -> bool {
        match self {
            Self::Main { .. } => false,
            #[cfg(test)]
            Self::ComponentNoNative { .. } => true,
        }
    }

    fn releases_actor(&self) -> bool {
        match self {
            Self::Main { .. } => true,
            #[cfg(test)]
            Self::ComponentNoNative { release_actor } => *release_actor,
        }
    }
}

/// Reports a startup refusal whose actual cause remains in its prepaid owner.
#[derive(Clone, Copy, Debug, Error)]
#[error("same prepaid Service startup phase refuses this request")]
pub(crate) struct RetainedServiceStartRefusal;

/// Retains only errors produced by the actual Service admission operations.
///
/// A complete packaged-executor error may itself own terminal Source custody.
/// Storing that general report inside its own Service would recurse through the
/// terminal body. These variants preserve the exact lower producer errors;
/// this phase cannot accept an executor/Source retirement report as admission.
#[derive(Debug, Error)]
pub(crate) enum RetainedServiceAdmissionError {
    /// The actual registry, cap, context or Original boundary refused.
    #[error(transparent)]
    HostOperational(#[from] HostOperationalError),
    /// The complete existing Service/World launch geometry cannot fit.
    #[error("host RAM launch admission failed: {0}")]
    HostRamAdmission(#[from] crucible_control_api::host_operational::HostRamAdmissionError),
    /// The retained input's actual checkpoint backend refused its binding.
    #[error(transparent)]
    Checkpoints(#[from] crate::ExactCheckpointStoreError),
    /// The existing semantic resource vector is invalid.
    #[error(transparent)]
    Codec(#[from] crucible_campaign::CampaignCodecError),
    /// The actual watchdog thread could not be constructed.
    #[error("packaged preparation supervision failed: {0}")]
    PreparationSupervisor(#[source] std::io::Error),
}

/// Owns partial or complete Service state in one original Main cleanup role.
///
/// This phase is never cloned or independently allocated. Successful startup
/// leaves its complete Service here through configuration and World admission.
pub(crate) struct RetainedServiceStart {
    phase: ServiceStartPhase,
    preclaim: Option<crate::lifecycle_cleanup::ServiceMainPreclaim>,
    attempted: bool,
    pending_selected_root: Option<crate::executor_supervisor::SelectedExactCheckpointRoot>,
    imported: Option<crate::imported_checkpoint::RetainedImportedCheckpoint>,
    imported_return: Option<crate::imported_checkpoint::ImportedCheckpointReturn>,
    imported_export_pending: bool,
    adopted_retirement_input: Option<ServiceRetirementInput>,
    imported_genesis_post: Option<crucible_host_resources::host_supervision::HostSupervisionError>,
    parent_receiver: Option<crate::ServiceMainReceiver>,
    parent_return_attempted: bool,
    parent_return_refused: bool,
    first: Option<RetainedServiceStartCause>,
    cleanup: Option<HostOperationalError>,
    admission: Option<crucible_host_resources::host_supervision::HostOperationGuard>,
    admission_post: Option<crucible_host_resources::host_supervision::HostSupervisionError>,
    projection_post: Option<crucible_host_resources::host_supervision::HostSupervisionError>,
    admission_completion_attempted: bool,
    admission_completion: Option<crucible_host_resources::host_supervision::HostSupervisionError>,
    authentication_original: Option<crucible_host_resources::host_supervision::HostOperationGuard>,
    authentication_completion_attempted: bool,
    authentication_completion:
        Option<crucible_host_resources::host_supervision::HostSupervisionError>,
}

/// Preserves the actual payer refusal or initiating Service failure.
#[derive(Debug, Error)]
pub(crate) enum RetainedServiceStartCause {
    /// The same genuine Main role refused before Service effects.
    #[error(transparent)]
    Preclaim(crate::lifecycle_cleanup::ServiceMainPreclaimError),
    /// The original selected-root slot refused before Service effects.
    #[error(transparent)]
    SelectedCheckpointSlot(crate::executor_worker::SelectedCheckpointSlotError),
    /// The actual Service startup or projection failed.
    #[error(transparent)]
    Admission(RetainedServiceAdmissionError),
    /// The actual parent's alias census refused before child control birth.
    #[error(transparent)]
    Parent(crate::PreparedSourceFailure),
    /// The admitted parent source could not be projected for genesis capture.
    #[error(transparent)]
    GenesisSource(crucible_engine::EngineError),
    /// A real caller Original refused during Service construction or projection.
    #[error(transparent)]
    Operational(crucible_host_resources::host_supervision::HostSupervisionError),
    /// The actual initial Preparation postcheck refused after successful work.
    #[error(transparent)]
    Post(crucible_host_resources::host_supervision::HostSupervisionError),
    /// The same initial Preparation completion refused after successful work.
    #[error(transparent)]
    Completion(crucible_host_resources::host_supervision::HostSupervisionError),
}

enum ServiceStartPhase {
    Empty,
    Partial(PartialServiceStart),
    Ready(RetainedTemplateService),
    Closing(PartialServiceStart),
    UnusedClosed,
}

struct PartialServiceStart {
    registry: crate::HostOperationalRegistry,
    owner: [u8; 32],
    supervisor: Option<HostOperationSupervisor>,
    prepared: Option<crucible_host_resources::host_supervision::PreparedHostOperationSupervisor>,
    preparation_custody: Arc<dyn Send + Sync>,
    capacity_custody: Arc<dyn Send + Sync>,
    input_retention: Option<Arc<dyn Send + Sync>>,
    reserved: bool,
    released: bool,
    completion_attempted: bool,
    complete_outer: bool,
    completion: Option<crucible_host_resources::host_supervision::HostSupervisionError>,
    watchdog: Option<AssignmentHostWatchdogGuard>,
    stop: Option<ServiceWatchdogStop>,
    watchdog_poisoned: bool,
    stop_poisoned: bool,
}

impl RetainedServiceStart {
    /// Initializes only inline storage; the caller retains the genuine preclaim.
    pub(crate) fn new(preclaim: crate::lifecycle_cleanup::ServiceMainPreclaim) -> Self {
        Self {
            preclaim: Some(preclaim),
            ..Self::empty_unbound()
        }
    }

    /// Initializes the same phase with actual input before any callback runs.
    pub(crate) fn new_with_import(
        preclaim: crate::lifecycle_cleanup::ServiceMainPreclaim,
        imported: crate::imported_checkpoint::RetainedImportedCheckpoint,
    ) -> Self {
        Self {
            imported: Some(imported),
            ..Self::new(preclaim)
        }
    }

    /// Initializes only a vacant move-replacement; it cannot start a Service.
    pub(crate) const fn empty_unbound() -> Self {
        Self {
            phase: ServiceStartPhase::Empty,
            preclaim: None,
            attempted: false,
            pending_selected_root: None,
            imported: None,
            imported_return: None,
            imported_export_pending: false,
            adopted_retirement_input: None,
            imported_genesis_post: None,
            parent_receiver: None,
            parent_return_attempted: false,
            parent_return_refused: false,
            first: None,
            cleanup: None,
            admission: None,
            admission_post: None,
            projection_post: None,
            admission_completion_attempted: false,
            admission_completion: None,
            authentication_original: None,
            authentication_completion_attempted: false,
            authentication_completion: None,
        }
    }

    /// Borrows a completely constructed Service without moving its custody.
    pub(crate) fn ready(&self) -> Option<&RetainedTemplateService> {
        match &self.phase {
            ServiceStartPhase::Ready(service) if self.first.is_none() => Some(service),
            _ => None,
        }
    }

    /// Borrows the actual initiating error, independently of later cleanup.
    pub(crate) fn first(&self) -> Option<&RetainedServiceStartCause> {
        self.first.as_ref()
    }

    /// Retains the exact preflight cause after its real input is Main-owned.
    pub(crate) fn record_initial_failure(&mut self, first: HostOperationalError) {
        if self.first.is_none() {
            self.first = Some(RetainedServiceStartCause::Admission(first.into()));
        }
    }

    /// Checks receiver binding while the actual capsule remains in this role.
    pub(crate) fn check_imported_receiver(
        &mut self,
        daemon: [u8; 32],
        checkpoints: &crate::ExactCheckpointStore,
    ) -> Result<(), RetainedServiceStartRefusal> {
        let result: Result<(), RetainedServiceAdmissionError> = (|| {
            let imported = self
                .imported
                .as_ref()
                .ok_or(HostOperationalError::Unavailable)?;
            if imported.authentication_owner().host_daemon_epoch() != daemon {
                return Err(HostOperationalError::Unavailable.into());
            }
            let basis = imported.basis().ok_or(HostOperationalError::Unavailable)?;
            checkpoints.require_reuse_backend(&basis.repository.blob_backend())?;
            Ok(())
        })();
        result.map_err(|first| self.refuse(first))
    }

    /// Retains the actual caller Original leaf before its body can be dropped.
    ///
    /// HostSupervisionError is Copy and carries no owning debt. This preserves
    /// the same typed first cause; it neither issues nor restarts an operation.
    pub(crate) fn record_external_supervision(
        &mut self,
        first: crucible_host_resources::host_supervision::HostSupervisionError,
    ) {
        if self.first.is_none() {
            self.first = Some(RetainedServiceStartCause::Operational(first));
        }
    }

    pub(super) fn retain_parent_before_service(
        &mut self,
        parent: &AttemptExecutionContext,
    ) -> Result<(), RetainedServiceAdmissionError> {
        if !matches!(self.phase, ServiceStartPhase::Empty) || self.parent_receiver.is_some() {
            return Err(HostOperationalError::Unavailable.into());
        }
        match parent.retain_service_receiver("retain borrowed Service ancestry") {
            Ok(receiver) => {
                self.parent_receiver = receiver;
                Ok(())
            }
            Err(first) => {
                if self.first.is_none() {
                    self.first = Some(RetainedServiceStartCause::Parent(first));
                }
                Err(HostOperationalError::Unavailable.into())
            }
        }
    }

    /// Borrows the actual once-joined watchdog history without extracting it.
    ///
    /// The panic payload remains actor-paid in Partial/Closing quarantine. This
    /// projection permits reporting its actual Any body before any disposal;
    /// neither a report nor its sign can return actor credit.
    pub(crate) fn with_watchdog_stop<R>(
        &self,
        apply: impl FnOnce(&ServiceWatchdogStop) -> R,
    ) -> Option<R> {
        self.watchdog_stop().map(apply)
    }

    fn watchdog_stop(&self) -> Option<&ServiceWatchdogStop> {
        match &self.phase {
            ServiceStartPhase::Partial(partial) | ServiceStartPhase::Closing(partial) => {
                partial.stop.as_ref()
            }
            ServiceStartPhase::Ready(_)
            | ServiceStartPhase::Empty
            | ServiceStartPhase::UnusedClosed => None,
        }
    }

    /// Borrows the actual first watchdog failure without moving its stop body.
    pub(crate) fn watchdog_first_failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        let stop = self.watchdog_stop()?;
        stop.watcher_failure
            .as_ref()
            .and_then(|history| {
                match history.trigger.as_ref() {
                    Some(
                        crate::supervision::ServiceWatchdogTrigger::Original(first)
                        | crate::supervision::ServiceWatchdogTrigger::Caller(first),
                    ) => Some(first as &dyn std::error::Error),
                    Some(crate::supervision::ServiceWatchdogTrigger::Cancellation) | None => None,
                }
                .or_else(|| {
                    history
                        .cancellation
                        .as_ref()
                        .map(|first| first as &dyn std::error::Error)
                })
                .or_else(|| {
                    history
                        .pager_cancellation
                        .as_ref()
                        .map(|first| first as &dyn std::error::Error)
                })
            })
            .or_else(|| {
                stop.completion
                    .as_ref()
                    .map(|first| first as &dyn std::error::Error)
            })
            .or_else(|| {
                stop.caller
                    .as_ref()
                    .map(|first| first as &dyn std::error::Error)
            })
            .or_else(|| {
                stop.cancellation
                    .as_ref()
                    .map(|first| first as &dyn std::error::Error)
            })
            .or_else(|| {
                stop.pager_cancellation
                    .as_ref()
                    .map(|first| first as &dyn std::error::Error)
            })
    }

    /// Visits each raw watchdog cause while its same actor-paid body stays held.
    ///
    /// The panic payload is Any rather than Error and remains available through
    /// with_watchdog_stop. Its retained body prevents actor credit from closing.
    pub(crate) fn visit_watchdog_history(
        &self,
        mut apply: impl FnMut(&'static str, &(dyn std::error::Error + 'static)),
    ) {
        let Some(stop) = self.watchdog_stop() else {
            return;
        };
        if let Some(first) = &stop.completion {
            apply("Service watchdog completion", first);
        }
        if let Some(first) = &stop.caller {
            apply("Service watchdog caller", first);
        }
        if let Some(first) = &stop.cancellation {
            apply("Service watchdog cancellation", first);
        }
        if let Some(first) = &stop.pager_cancellation {
            apply("Service watchdog pager cancellation", first);
        }
        if let Some(history) = &stop.watcher_failure {
            match &history.trigger {
                Some(crate::supervision::ServiceWatchdogTrigger::Original(first)) => {
                    apply("Service watcher Original", first);
                }
                Some(crate::supervision::ServiceWatchdogTrigger::Caller(first)) => {
                    apply("Service watcher caller", first);
                }
                Some(crate::supervision::ServiceWatchdogTrigger::Cancellation) | None => {}
            }
            if let Some(first) = &history.cancellation {
                apply("Service watcher cancellation", first);
            }
            if let Some(first) = &history.pager_cancellation {
                apply("Service watcher pager cancellation", first);
            }
        }
    }

    /// Borrows completion failures retained outside the watchdog stop journal.
    pub(crate) fn retained_completion_failure(
        &self,
    ) -> Option<&crucible_host_resources::host_supervision::HostSupervisionError> {
        self.authentication_completion
            .as_ref()
            .or_else(|| match &self.phase {
                ServiceStartPhase::Partial(partial) | ServiceStartPhase::Closing(partial) => {
                    partial.completion.as_ref()
                }
                ServiceStartPhase::Ready(_)
                | ServiceStartPhase::Empty
                | ServiceStartPhase::UnusedClosed => None,
            })
    }

    /// Visits both independent completions without copying their raw leaves.
    pub(crate) fn visit_retained_completion_history(
        &self,
        mut apply: impl FnMut(&'static str, &(dyn std::error::Error + 'static)),
    ) {
        if let Some(first) = &self.authentication_completion {
            apply("Service authentication completion", first);
        }
        if let ServiceStartPhase::Partial(partial) | ServiceStartPhase::Closing(partial) =
            &self.phase
            && let Some(first) = &partial.completion
        {
            apply("Service outer completion", first);
        }
    }

    /// Borrows the independent raw postcheck of the initial Service admission.
    pub(crate) fn admission_post_failure(
        &self,
    ) -> Option<&crucible_host_resources::host_supervision::HostSupervisionError> {
        self.admission_post.as_ref()
    }

    /// Borrows the independent raw postcheck of a later semantic projection.
    pub(crate) fn projection_post_failure(
        &self,
    ) -> Option<&crucible_host_resources::host_supervision::HostSupervisionError> {
        self.projection_post.as_ref()
    }

    /// Borrows the same admission's once-attempted completion refusal.
    pub(crate) fn admission_completion_failure(
        &self,
    ) -> Option<&crucible_host_resources::host_supervision::HostSupervisionError> {
        self.admission_completion.as_ref()
    }

    /// Borrows raw import facts after its decoded and Original bodies return.
    pub(crate) fn imported_return(
        &self,
    ) -> Option<&crate::imported_checkpoint::ImportedCheckpointReturn> {
        self.imported_return.as_ref()
    }

    /// Borrows the first independent actor-cleanup refusal.
    pub(crate) fn cleanup_failure(&self) -> Option<&HostOperationalError> {
        self.cleanup.as_ref()
    }

    /// Borrows the original semantic shutdown cause from adopted input.
    pub(crate) fn adopted_semantic_shutdown_failure(&self) -> Option<&crucible_engine::SchedulerError> {
        self.adopted_retirement_input
            .as_ref()
            .and_then(ServiceRetirementInput::semantic_shutdown_failure)
    }

    /// Binds an authenticated finding under the SAME existing Restore guard.
    ///
    /// This projects semantic identity only. It neither restarts startup nor
    /// borrows a different roster merely because that roster shares a cap.
    ///
    /// # Errors
    /// Reports a foreign/expired guard, unavailable phase, changed root or raw
    /// post refusal while retaining actual first and post facts in this cell.
    pub(crate) fn bind_authenticated_finding_debug(
        &mut self,
        checkpoint: crucible_campaign::ExactCheckpointId,
        selected: &mut Option<crate::executor_supervisor::SelectedExactCheckpointRoot>,
        original: &crucible_host_resources::host_supervision::HostOperationGuard,
    ) -> Result<(), RetainedServiceStartRefusal> {
        let result: Result<(), RetainedServiceAdmissionError> = (|| {
            original
                .verify_operation_class(
                    crucible_host_resources::host_supervision::HostOperationClass::Restore,
                )
                .map_err(|source| HostOperationalError::OriginalBoundary { source })?;
            let service = match &mut self.phase {
                ServiceStartPhase::Ready(service) if self.first.is_none() => service,
                _ => return Err(HostOperationalError::Unavailable.into()),
            };
            let supervisor = service
                .context()
                .host_operation_supervisor()
                .ok_or(HostOperationalError::Unavailable)?;
            if !original.belongs_to_supervisor(supervisor) {
                return Err(HostOperationalError::Unavailable.into());
            }
            service
                .bind_authenticated_finding_debug(checkpoint, selected)
                .map_err(Into::into)
        })();
        let post = original.wait_slice().err();
        match result {
            Err(first) => {
                if self.projection_post.is_none() {
                    self.projection_post = post;
                }
                Err(self.refuse(first))
            }
            Ok(()) => {
                if let Some(first) = post {
                    self.projection_post = Some(first);
                    self.first = Some(RetainedServiceStartCause::Post(first));
                    Err(RetainedServiceStartRefusal)
                } else {
                    Ok(())
                }
            }
        }
    }

    /// Observes actual Service discharge independently of earlier failures.
    pub(crate) fn is_released(&self) -> bool {
        let aliases_returned = self
            .adopted_retirement_input
            .as_ref()
            .is_none_or(|input| input.is_returned());
        aliases_returned
            && self.pending_selected_root.is_none()
            && match &self.phase {
                ServiceStartPhase::Partial(partial) | ServiceStartPhase::Closing(partial) => {
                    partial.released
                        && self.parent_receiver.is_none()
                        && self
                            .imported_return
                            .as_ref()
                            .is_none_or(|returned| returned.parent_returned())
                }
                ServiceStartPhase::Ready(_) => false,
                ServiceStartPhase::UnusedClosed => {
                    self.parent_receiver.is_none()
                        && self
                            .imported_return
                            .as_ref()
                            .is_none_or(|returned| returned.parent_returned())
                }
                ServiceStartPhase::Empty => false,
            }
    }

    /// Checks the one cleanup-only slot before moving any original input.
    pub(crate) fn can_adopt_retirement_input(&self, input: &ServiceRetirementInput) -> bool {
        self.adopted_retirement_input.is_none()
            && self.imported.is_none()
            && self
                .preclaim
                .as_ref()
                .is_some_and(|key| input.matches_main_role(key))
            && matches!(
                self.phase,
                ServiceStartPhase::Ready(_) | ServiceStartPhase::Closing(_)
            )
    }

    /// Moves one already admitted input after validating the whole transfer.
    ///
    /// This method performs no IO, destructor, Original check or admission.
    /// Refusal leaves the actual caller-owned value intact.
    pub(crate) fn adopt_retirement_input(
        &mut self,
        input: &mut Option<ServiceRetirementInput>,
    ) -> Result<(), &'static str> {
        let Some(candidate) = input.as_ref() else {
            return Err("receiving retirement input is absent");
        };
        if !self.can_adopt_retirement_input(candidate) {
            return Err("receiving retirement input differs from the same vacant Service role");
        }
        self.adopted_retirement_input = input.take();
        Ok(())
    }

    /// Disposes adopted aliases only after Main's genuine World/body return.
    ///
    /// The canonical driver invokes this BEFORE testing external receivers. The
    /// same output token is acknowledged only after actual input destruction;
    /// normal child-control/Service closure still occurs afterward.
    pub(crate) fn retry_adopted_aliases_after_world_cleanup(&mut self) -> bool {
        self.adopted_retirement_input
            .as_mut()
            .is_none_or(|input| input.retry_after_world_cleanup())
    }

    /// Disposes adopted aliases under Main's exact World-not-started journal.
    ///
    /// An absent callback or body is insufficient. The canonical producer must
    /// establish its genuine NotStarted state before invoking this projection.
    pub(crate) fn retry_adopted_aliases_before_world_cleanup(&mut self) -> bool {
        self.adopted_retirement_input
            .as_mut()
            .is_none_or(|input| input.retry_after_world_cleanup())
    }

    /// Borrows actual cleanup history of the absorbed maintenance Original.
    pub(crate) fn adopted_retirement_return(
        &self,
    ) -> Option<&crate::imported_checkpoint::ImportedCheckpointReturn> {
        self.adopted_retirement_input
            .as_ref()
            .and_then(|input| input.returned())
    }

    /// Corroborates the original Main role without issuing another reservation.
    pub(crate) fn matches_main_role(
        &self,
        preclaim: &crate::lifecycle_cleanup::ServiceMainPreclaim,
    ) -> bool {
        self.preclaim
            .as_ref()
            .is_some_and(|own| own.same_role(preclaim))
    }

    /// Permits an ordinary unused path or a completely ready Service path.
    pub(crate) fn world_start_is_allowed(&self) -> bool {
        (!self.attempted
            && self.preclaim.is_some()
            && self.first.is_none()
            && self.imported.is_none()
            && self.parent_receiver.is_none()
            && matches!(self.phase, ServiceStartPhase::Empty))
            || self.ready().is_some()
    }

    /// Corroborates the actual retained Service against the World input.
    pub(crate) fn matches_world_context(&self, context: &AttemptExecutionContext) -> bool {
        if !self.attempted
            && self.preclaim.is_some()
            && self.first.is_none()
            && self.imported.is_none()
            && self.parent_receiver.is_none()
            && matches!(self.phase, ServiceStartPhase::Empty)
        {
            return true;
        }
        let Some(service) = self.ready() else {
            return false;
        };
        let retained = service.context();
        if !matches!(
            retained.host_outer_cap_owner(),
            Some(crucible_control_api::host_operational::HostOuterCapOwner::Service(
                _
            ))
        ) || retained.host_outer_cap_owner() != context.host_outer_cap_owner()
            || retained.host_daemon_epoch() != context.host_daemon_epoch()
            || !retained
                .cancellation()
                .same_incarnation(context.cancellation())
        {
            return false;
        }
        match (
            retained.host_operation_supervisor(),
            context.host_operation_supervisor(),
        ) {
            (Some(retained), Some(input)) => {
                retained == input
                    && retained.cap_id() == input.cap_id()
                    && retained.shares_outer_cap(input)
            }
            _ => false,
        }
    }

    /// Retries closure only under the producer's explicit WorldNotStarted fact.
    pub(crate) fn retry_before_world_cleanup(&mut self) -> bool {
        self.retry_cleanup(ServiceCleanupBoundary::Main {
            world_returned: false,
        })
    }

    /// Retries closure after actual World/body and external borrower return.
    ///
    /// The owning Main cell establishes that physical cut; a ledger query or
    /// the absence of a callback is never sufficient to select this method.
    pub(crate) fn retry_after_world_cleanup(&mut self) -> bool {
        self.retry_cleanup(ServiceCleanupBoundary::Main {
            world_returned: true,
        })
    }

    /// Cancels only the pending export intent after a real owning failure.
    ///
    /// The Main queue applies its negative-only journal before this phase's
    /// cleanup. This changes no World-return or alias-destruction fact.
    pub(crate) fn abandon_imported_export(&mut self) {
        self.imported_export_pending = false;
    }

    fn retry_cleanup(&mut self, boundary: ServiceCleanupBoundary) -> bool {
        let world_returned = boundary.world_returned();
        if self
            .adopted_retirement_input
            .as_ref()
            .is_some_and(|input| !input.is_returned())
        {
            // Reabsorbing the real aliases is not their destruction. Preserve
            // every Service control and its actor debit until the proven-cut
            // input tail has disposed them and returned its exact token.
            return false;
        }
        if world_returned && self.imported_export_pending {
            // Successful genesis exports its untouched parent-paid input only
            // at the Main queue's genuine World/body/alias-return cut. Closing
            // must not destroy that input before the checked extraction.
            return false;
        }
        // Only this producer-selected no-World/returned-World tail may
        // destroy a root whose Service admission stopped after its transfer.
        drop(self.pending_selected_root.take());
        if self.authentication_original.is_some() {
            // Cleanup uses the same saved original even after initiating
            // refusal. Its sign is retained separately from physical closure.
            let _completion = self.complete_authentication_original();
        }
        if matches!(self.phase, ServiceStartPhase::Ready(_)) {
            let previous = std::mem::replace(&mut self.phase, ServiceStartPhase::Empty);
            match previous {
                ServiceStartPhase::Ready(service) => {
                    self.phase = ServiceStartPhase::Closing(service.into_closing());
                }
                previous => self.phase = previous,
            }
        }
        drop(self.authentication_original.take());
        let result = match &mut self.phase {
            ServiceStartPhase::Empty
                if self.preclaim.is_some() || boundary.allows_empty_component() =>
            {
                // This explicit phase has never installed a Service body. The
                // owning producer still establishes the World-not-started cut.
                if let Some(imported) = self.imported.take() {
                    self.imported_return = Some(imported.retire_unpublished());
                }
                self.phase = ServiceStartPhase::UnusedClosed;
                return self.retry_parent_returns();
            }
            ServiceStartPhase::UnusedClosed => return self.retry_parent_returns(),
            ServiceStartPhase::Partial(partial) if !world_returned => partial.retry_cleanup(
                &mut self.admission,
                &mut self.imported,
                &mut self.imported_return,
                boundary.releases_actor(),
            ),
            ServiceStartPhase::Closing(partial) => partial.retry_cleanup(
                &mut self.admission,
                &mut self.imported,
                &mut self.imported_return,
                boundary.releases_actor(),
            ),
            _ => return false,
        };
        match result {
            Ok(()) => self.retry_parent_returns(),
            Err(first) => {
                if self.cleanup.is_none() {
                    self.cleanup = Some(first);
                }
                false
            }
        }
    }

    fn retry_parent_returns(&mut self) -> bool {
        if let Some(returned) = &mut self.imported_return
            && !returned.retry_parent_return()
        {
            return false;
        }
        let Some(receiver) = self.parent_receiver.take() else {
            return true;
        };
        // Both capsule aliases and every child control/actor have already been
        // destroyed. This same-parent acknowledgment uses nonblocking atomics;
        // it never waits for parent finality while holding the child role.
        self.parent_return_attempted = true;
        match receiver.return_after_alias_destruction() {
            Ok(()) => true,
            Err(receiver) => {
                self.parent_return_refused = true;
                self.parent_receiver = Some(receiver);
                false
            }
        }
    }

    /// Moves the actual original selection directly into its prepaid phase.
    pub(super) fn retain_resume_root(
        &mut self,
        original: &AttemptExecutionContext,
        checkpoint: crucible_campaign::ExactCheckpointId,
    ) -> Result<(), RetainedServiceAdmissionError> {
        if self.pending_selected_root.is_some() {
            return Err(HostOperationalError::Unavailable.into());
        }
        match original.try_take_selected_checkpoint_for(checkpoint) {
            Ok(Some(selected)) => {
                self.pending_selected_root = Some(selected);
                Ok(())
            }
            Ok(None) => Err(HostOperationalError::InvalidMessage {
                message: "selected exact root differs from the requested retained source"
                    .to_owned(),
            }
            .into()),
            Err(first) => {
                if self.first.is_none() {
                    self.first = Some(RetainedServiceStartCause::SelectedCheckpointSlot(first));
                }
                Err(HostOperationalError::Unavailable.into())
            }
        }
    }

    /// Selects a new reconciled root only while its actual Main phase is held.
    ///
    /// The producer is never invoked on an occupied or used phase. Its root
    /// moves directly here before validation or any later fallible operation;
    /// the producer's actual error returns separately without inventing one.
    pub(crate) fn retain_reconciled_replay_root<E>(
        &mut self,
        checkpoint: crucible_campaign::ExactCheckpointId,
        select: impl FnOnce() -> Result<
            Option<crate::executor_supervisor::SelectedExactCheckpointRoot>,
            E,
        >,
    ) -> Result<Result<(), E>, RetainedServiceStartRefusal> {
        if self.attempted
            || self.first.is_some()
            || self.preclaim.is_none()
            || !matches!(self.phase, ServiceStartPhase::Empty)
            || self.pending_selected_root.is_some()
        {
            return Err(RetainedServiceStartRefusal);
        }
        self.verify_preclaim()?;
        self.pending_selected_root = match select() {
            Ok(selected) => selected,
            Err(first) => return Ok(Err(first)),
        };
        if let Err(first) = self.validate_pending_replay_root(Some(checkpoint)) {
            return Err(self.refuse(first));
        }
        Ok(Ok(()))
    }

    pub(super) fn validate_pending_replay_root(
        &self,
        checkpoint: Option<crucible_campaign::ExactCheckpointId>,
    ) -> Result<(), RetainedServiceAdmissionError> {
        match (checkpoint, self.pending_selected_root.as_ref()) {
            (Some(checkpoint), Some(root)) if root.authorizes(checkpoint) => Ok(()),
            (None, None) => Ok(()),
            _ => Err(HostOperationalError::InvalidMessage {
                message: "replay source differs from its selected exact root".into(),
            }
            .into()),
        }
    }

    /// Transfers the saved root only into the actual Ready Service context.
    pub(super) fn bind_pending_resume_basis(
        &mut self,
        original: &AttemptExecutionContext,
    ) -> Result<(), RetainedServiceAdmissionError> {
        if self.pending_selected_root.is_none() {
            return Err(HostOperationalError::Unavailable.into());
        }
        self.bind_pending_selection(|context| context.clone().with_semantic_resume_basis(original))
    }

    pub(super) fn bind_pending_replay_basis(
        &mut self,
        basis: &crate::qemu_baked_genesis::ProductionCheckpointReplayBasis,
    ) -> Result<(), RetainedServiceAdmissionError> {
        self.bind_pending_selection(|context| {
            context.clone().with_semantic_replay_basis(
                basis.resources(),
                basis.runtime_basis(),
                basis.start_mode(),
            )
        })
    }

    fn bind_pending_selection(
        &mut self,
        project: impl FnOnce(&AttemptExecutionContext) -> AttemptExecutionContext,
    ) -> Result<(), RetainedServiceAdmissionError> {
        // Preserve the existing same-admission check before context binding.
        // Its refusal leaves the saved root inside this phase.
        self.ready_mut()?;
        let ServiceStartPhase::Ready(service) = &mut self.phase else {
            return Err(HostOperationalError::Unavailable.into());
        };
        // Every refusal precedes the take. Context projection preserves the
        // existing semantic algorithm and never clones selected authority.
        service.context = project(&service.context)
            .install_selected_checkpoint(self.pending_selected_root.take());
        Ok(())
    }

    fn verify_preclaim(&mut self) -> Result<(), RetainedServiceStartRefusal> {
        let verified = match &self.preclaim {
            Some(preclaim) => preclaim.verify_before_service(),
            None => Err(crate::lifecycle_cleanup::ServiceMainPreclaimError::Role(
                "retain the same Main role before Service startup",
            )),
        };
        if let Err(first) = verified {
            self.first = Some(RetainedServiceStartCause::Preclaim(first));
            return Err(RetainedServiceStartRefusal);
        }
        Ok(())
    }

    pub(super) fn run(
        &mut self,
        operation: impl FnOnce(&mut Self) -> Result<(), RetainedServiceAdmissionError>,
    ) -> Result<(), RetainedServiceStartRefusal> {
        if self.attempted || self.first.is_some() || !matches!(self.phase, ServiceStartPhase::Empty)
        {
            return Err(RetainedServiceStartRefusal);
        }
        self.verify_preclaim()?;
        self.run_admission(operation)
    }

    /// Runs the common actor operation and its same-original post/completion.
    ///
    /// Production reaches this only after verify_preclaim. The private component
    /// owner supplies stack custody and no native context binding or entrypoint.
    fn run_admission(
        &mut self,
        operation: impl FnOnce(&mut Self) -> Result<(), RetainedServiceAdmissionError>,
    ) -> Result<(), RetainedServiceStartRefusal> {
        let result = operation(self);
        // Always retain the actual post independently of the initiating error.
        // No retry can enter or complete a replacement admission Original.
        if let Some(admission) = self.admission.as_ref() {
            self.admission_post = admission.wait_slice().err();
            if !self.admission_completion_attempted {
                self.admission_completion_attempted = true;
                self.admission_completion = admission.complete().err();
            }
        }
        match result {
            Err(first) => Err(self.refuse(first)),
            Ok(value) => {
                if let Some(first) = self.admission_post {
                    self.first = Some(RetainedServiceStartCause::Post(first));
                    return Err(RetainedServiceStartRefusal);
                }
                if let Some(first) = self.admission_completion {
                    self.first = Some(RetainedServiceStartCause::Completion(first));
                    return Err(RetainedServiceStartRefusal);
                }
                Ok(value)
            }
        }
    }

    pub(super) fn start(
        &mut self,
        factory: &RetainedTemplateServiceFactory,
        scenario: &ScenarioDefForm,
        checkpoint: Option<crucible_campaign::ExactCheckpointId>,
        headroom: ServiceHeadroom,
        purpose: ServicePurpose,
        cancellation: ExecutionCancellation,
    ) -> Result<(), RetainedServiceAdmissionError> {
        Self::start_fields(
            &mut self.attempted,
            &mut self.phase,
            &mut self.admission,
            ServiceContextBinding::Main(self.preclaim.as_ref()),
            factory,
            scenario,
            checkpoint,
            headroom,
            purpose,
            cancellation,
        )
    }

    fn start_fields(
        attempted: &mut bool,
        phase: &mut ServiceStartPhase,
        admission: &mut Option<crucible_host_resources::host_supervision::HostOperationGuard>,
        binding: ServiceContextBinding<'_>,
        factory: &RetainedTemplateServiceFactory,
        scenario: &ScenarioDefForm,
        checkpoint: Option<crucible_campaign::ExactCheckpointId>,
        headroom: ServiceHeadroom,
        purpose: ServicePurpose,
        cancellation: ExecutionCancellation,
    ) -> Result<(), RetainedServiceAdmissionError> {
        if *attempted || !matches!(phase, ServiceStartPhase::Empty) {
            return Err(HostOperationalError::Unavailable.into());
        }
        *attempted = true;
        let policy = &factory.policy;
        let service = policy
            .retained_template_resources
            .ok_or(HostOperationalError::Unavailable)?;
        let assignment = policy
            .assignment_resources
            .ok_or(HostOperationalError::Unavailable)?;
        let quanta = policy
            .assignment_limits
            .ok_or(HostOperationalError::Unavailable)?
            .maximum_execution_quanta();
        // The watcher is outside every node partition. Its full stack remains
        // charged even while the source performs no operational work.
        let service_resident = policy.watcher_service_resident_bytes;
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
        let budgets = policy
            .host_operation_budgets
            .ok_or(HostOperationalError::Unavailable)?;
        let prepared = HostOperationSupervisor::prepare(budgets, None)
            .map_err(|source| HostOperationalError::OriginalBoundary { source })?;
        let owner_nonce = prepared.cap_id();
        let daemon =
            crate::host_operational_registry::operational_identity(policy.daemon_epoch.as_bytes());
        let mut owner_digest = blake3::Hasher::new();
        owner_digest.update(b"crucible.host.retained-template-owner.v1\0");
        owner_digest.update(&daemon);
        owner_digest.update(&owner_nonce);
        let owner = *owner_digest.finalize().as_bytes();
        let registry = factory.registry.clone();
        let capacity_custody = registry.capacity_custody()?;
        *phase = ServiceStartPhase::Partial(PartialServiceStart {
            registry: registry.clone(),
            owner,
            supervisor: None,
            prepared: Some(prepared),
            preparation_custody: Arc::clone(&factory.preparation_custody),
            capacity_custody,
            input_retention: factory.input_retention.clone(),
            reserved: false,
            released: false,
            completion_attempted: false,
            complete_outer: factory.outer_supervisor.is_none(),
            completion: None,
            watchdog: None,
            stop: None,
            watchdog_poisoned: false,
            stop_poisoned: false,
        });
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
        let ServiceStartPhase::Partial(partial) = &mut *phase else {
            return Err(HostOperationalError::Unavailable.into());
        };
        // The actual actor commits only on Ok. Record that fact before the
        // first fallible configuration, watcher or context operation.
        partial.reserved = true;
        // The complete actual Service debit precedes all shared controls.
        let supervisor = match &factory.outer_supervisor {
            Some(original) => original.new_budget_owner(budgets),
            None => partial
                .prepared
                .take()
                .ok_or(HostOperationalError::Unavailable)?
                .publish(),
        }
        .map_err(|source| HostOperationalError::OriginalBoundary { source })?;
        partial.supervisor = Some(supervisor.clone());
        *admission = Some(
            supervisor
                .begin(crucible_host_resources::host_supervision::HostOperationClass::Preparation)
                .map_err(|source| HostOperationalError::OriginalBoundary { source })?,
        );
        admission
            .as_ref()
            .ok_or(HostOperationalError::Unavailable)?
            .wait_slice()
            .map_err(|source| HostOperationalError::OriginalBoundary { source })?;
        // Temporary shape storage is inside the real Service debit and its
        // entered Original. A refusal retains both in this same Main phase.
        validate_world_floor(
            &factory.registry,
            scenario,
            resources,
            service,
            service_resident,
        )?;
        admission
            .as_ref()
            .ok_or(HostOperationalError::Unavailable)?
            .wait_slice()
            .map_err(|source| HostOperationalError::OriginalBoundary { source })?;
        registry.configure_owner(daemon, owner, node_ceiling)?;
        admission
            .as_ref()
            .ok_or(HostOperationalError::Unavailable)?
            .wait_slice()
            .map_err(|source| HostOperationalError::OriginalBoundary { source })?;
        let watchdog = if factory.outer_supervisor.is_some() {
            AssignmentHostWatchdogGuard::start_borrowed_service(
                supervisor,
                cancellation.clone(),
                Some(registry.clone()),
            )
        } else {
            AssignmentHostWatchdogGuard::start_service(
                supervisor,
                cancellation.clone(),
                Some(registry.clone()),
            )
        }
        .map_err(RetainedServiceAdmissionError::PreparationSupervisor)?;
        partial.watchdog = Some(watchdog);
        admission
            .as_ref()
            .ok_or(HostOperationalError::Unavailable)?
            .wait_slice()
            .map_err(|source| HostOperationalError::OriginalBoundary { source })?;
        let watchdog = partial
            .watchdog
            .as_ref()
            .ok_or(HostOperationalError::Unavailable)?;
        let mut context = AttemptExecutionContext::for_preparation_service(
            resources,
            registry.clone(),
            daemon,
            owner,
            watchdog.state.clone(),
            cancellation,
        )?;
        binding.stamp(&mut context)?;
        let context = match purpose {
            ServicePurpose::RetainedTemplate => context.with_retained_template_role()?,
            ServicePurpose::Replay => context,
        };
        // All required parts remain in the same inline phase until the last
        // fallible startup operation succeeds. No failure-time owner is born.
        let service = RetainedTemplateService {
            native_context: context.clone().with_resume_checkpoint(checkpoint),
            context: context.with_resume_checkpoint(checkpoint),
            watchdog: Mutex::new(partial.watchdog.take()),
            watchdog_stop: Mutex::new(None),
            registry,
            owner,
            preparation_custody: Arc::clone(&partial.preparation_custody),
            _input_retention: partial.input_retention.clone(),
            _capacity_custody: Arc::clone(&partial.capacity_custody),
        };
        *phase = ServiceStartPhase::Ready(service);
        Ok(())
    }

    pub(super) fn start_imported(
        &mut self,
        factory: &RetainedTemplateServiceFactory,
        cancellation: ExecutionCancellation,
        maintenance: bool,
    ) -> Result<(), RetainedServiceAdmissionError> {
        let imported = self
            .imported
            .as_mut()
            .ok_or(HostOperationalError::Unavailable)?;
        let constrained;
        let factory = if maintenance {
            let original = imported
                .authentication_owner()
                .host_operation_supervisor()
                .ok_or(HostOperationalError::Unavailable)?;
            constrained = factory.clone().with_outer_supervisor(original.clone());
            &constrained
        } else {
            factory
        };
        if let Some(outer) = &factory.outer_supervisor {
            // The actual shared outer establishes ancestry; no reference count
            // or copied cap can stand in for this same owning receiver.
            self.parent_receiver = imported.take_shared_parent_receiver(outer);
        }
        let basis = imported.basis().ok_or(HostOperationalError::Unavailable)?;
        let requested = basis.resources;
        let budgets = basis.budgets;
        let checkpoint = basis.checkpoint;
        if imported.authentication_owner().cancellation().is_canceled()
            || imported
                .authentication_owner()
                .host_ram_resource_ceiling()
                .is_none()
        {
            return Err(HostOperationalError::Unavailable.into());
        }
        if !maintenance {
            budgets
                .validate(false)
                .map_err(|source| HostOperationalError::OriginalBoundary { source })?;
        }
        let ceiling = factory
            .policy
            .assignment_limits
            .ok_or(HostOperationalError::Unavailable)?;
        if requested.maximum_vcpus() > ceiling.maximum_vcpus()
            || requested.maximum_resident_bytes() > ceiling.maximum_resident_bytes()
            || requested.maximum_disk_bytes() > ceiling.maximum_disk_bytes()
            || requested.maximum_execution_quanta() > ceiling.maximum_execution_quanta()
        {
            return Err(HostOperationalError::InvalidMessage {
                message: if maintenance {
                    "maintenance import exceeds receiver assignment limits"
                } else {
                    "imported replay exceeds receiver assignment limits"
                }
                .into(),
            }
            .into());
        }
        Self::start_fields(
            &mut self.attempted,
            &mut self.phase,
            &mut self.admission,
            ServiceContextBinding::Main(self.preclaim.as_ref()),
            factory,
            &basis.source,
            Some(checkpoint),
            ServiceHeadroom::FutureAssignment,
            ServicePurpose::Replay,
            cancellation,
        )?;
        self.admission
            .as_ref()
            .ok_or(HostOperationalError::Unavailable)?
            .wait_slice()
            .map_err(|source| HostOperationalError::OriginalBoundary { source })?;
        let service = match &mut self.phase {
            ServiceStartPhase::Ready(service) => service,
            _ => return Err(HostOperationalError::Unavailable.into()),
        };
        if !maintenance {
            service
                .context
                .host_operation_supervisor()
                .ok_or(HostOperationalError::Unavailable)?
                .update_budgets(0, budgets)
                .map_err(|source| HostOperationalError::OriginalBoundary { source })?;
        }
        let selected = imported
            .prepare_launch(maintenance)
            .map_err(|source| HostOperationalError::OriginalBoundary { source })?;
        service.context = service
            .context
            .clone()
            .with_service_resources(requested)
            .install_selected_checkpoint(Some(selected));
        Ok(())
    }

    pub(crate) fn take_imported_basis(
        &mut self,
    ) -> Result<crate::imported_checkpoint::ImportedCheckpointBasis, RetainedServiceStartRefusal>
    {
        if self.first.is_some()
            || !self.admission_completion_attempted
            || self.admission_post.is_some()
            || self.admission_completion.is_some()
            || !matches!(self.phase, ServiceStartPhase::Ready(_))
        {
            return Err(RetainedServiceStartRefusal);
        }
        let imported = self.imported.take().ok_or(RetainedServiceStartRefusal)?;
        match imported.take_launch_output() {
            Ok((basis, returned)) => {
                self.imported_return = Some(returned);
                Ok(basis)
            }
            Err(imported) => {
                self.imported = Some(imported);
                Err(RetainedServiceStartRefusal)
            }
        }
    }

    pub(crate) fn take_maintenance_output<'owner>(
        &mut self,
        owner: crate::imported_checkpoint::ImportedCheckpointOwner<'owner>,
    ) -> Result<
        (
            crate::imported_checkpoint::ImportedCheckpointBasis,
            crate::imported_checkpoint::ImportedCheckpointMaintenance<'owner>,
        ),
        RetainedServiceStartRefusal,
    > {
        if self.first.is_some()
            || !self.admission_completion_attempted
            || self.admission_post.is_some()
            || self.admission_completion.is_some()
            || !matches!(self.phase, ServiceStartPhase::Ready(_))
        {
            return Err(RetainedServiceStartRefusal);
        }
        let imported = self.imported.take().ok_or(RetainedServiceStartRefusal)?;
        match imported.take_maintenance_output(owner) {
            Ok(output) => Ok(output),
            Err((imported, _owner)) => {
                self.imported = Some(imported);
                Err(RetainedServiceStartRefusal)
            }
        }
    }

    fn refuse(&mut self, first: RetainedServiceAdmissionError) -> RetainedServiceStartRefusal {
        if self.first.is_none() {
            self.first = Some(RetainedServiceStartCause::Admission(first));
        }
        RetainedServiceStartRefusal
    }

    pub(super) fn ready_mut(
        &mut self,
    ) -> Result<&mut RetainedTemplateService, HostOperationalError> {
        self.admission
            .as_ref()
            .ok_or(HostOperationalError::Unavailable)?
            .wait_slice()
            .map_err(|source| HostOperationalError::OriginalBoundary { source })?;
        match &mut self.phase {
            ServiceStartPhase::Ready(service) if self.first.is_none() => Ok(service),
            _ => Err(HostOperationalError::Unavailable),
        }
    }
}

impl PartialServiceStart {
    fn retry_cleanup(
        &mut self,
        admission: &mut Option<crucible_host_resources::host_supervision::HostOperationGuard>,
        imported: &mut Option<crate::imported_checkpoint::RetainedImportedCheckpoint>,
        imported_return: &mut Option<crate::imported_checkpoint::ImportedCheckpointReturn>,
        release_actor: bool,
    ) -> Result<(), HostOperationalError> {
        if self.released {
            return Ok(());
        }
        if let Some(watchdog) = self.watchdog.take() {
            // Consumption is stored before actor discharge; negative Original
            // completion cannot cause a second join on a subsequent retry.
            self.stop = Some(watchdog.stop_service_owned());
            self.completion_attempted = true;
        } else if !self.completion_attempted {
            self.completion_attempted = true;
            if self.complete_outer
                && let Some(supervisor) = &self.supervisor
            {
                self.completion = supervisor.complete().err();
            }
        }
        // The actual body/borrower cut preceded this Closing phase. Joining
        // precedes each known Service alias return; cap controls then disappear
        // inside registry retirement before the actor subtracts its vector.
        if let Some(imported) = imported.take() {
            *imported_return = Some(imported.retire_unpublished());
        }
        drop(admission.take());
        drop(self.supervisor.take());
        drop(self.prepared.take());
        if self
            .stop
            .as_ref()
            .is_some_and(|stop| stop.join_failure.is_some())
        {
            // The actor still pays the actual panic body. A fixed Main slot
            // prices this pointer, not that body; terminal reporting/disposal
            // must destroy it before the same actor credit can return.
            return Err(HostOperationalError::Unavailable);
        }
        if self.reserved && release_actor {
            self.registry.release_service_after_cleanup(self.owner)?;
        }
        self.released = !self.reserved || release_actor;
        Ok(())
    }
}

impl RetainedTemplateService {
    fn into_closing(self) -> PartialServiceStart {
        let Self {
            context,
            native_context,
            watchdog,
            watchdog_stop,
            registry,
            owner,
            preparation_custody,
            _input_retention,
            _capacity_custody,
        } = self;
        let (watchdog, watchdog_poisoned) = match watchdog.into_inner() {
            Ok(watchdog) => (watchdog, false),
            Err(poisoned) => (poisoned.into_inner(), true),
        };
        let (stop, stop_poisoned) = match watchdog_stop.into_inner() {
            Ok(stop) => (stop, false),
            Err(poisoned) => (poisoned.into_inner(), true),
        };
        drop(context);
        drop(native_context);
        PartialServiceStart {
            registry,
            owner,
            supervisor: None,
            prepared: None,
            preparation_custody,
            capacity_custody: _capacity_custody,
            input_retention: _input_retention,
            reserved: true,
            released: false,
            completion_attempted: stop.is_some(),
            complete_outer: false,
            completion: None,
            watchdog,
            stop,
            watchdog_poisoned,
            stop_poisoned,
        }
    }
}
