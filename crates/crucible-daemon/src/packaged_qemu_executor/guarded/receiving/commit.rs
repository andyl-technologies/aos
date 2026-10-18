//! Local live-owner pairing for durable source release and receiving commit.
//!
//! The receiving journal is never a constructor for these capabilities. This
//! path requires both original charged actors and the actual stopped World in
//! this process. It leaves the World opaque after commit: authenticated remote
//! deployment and the executable handoff consumer remain separate obligations.

use super::*;
use crate::assignment_ledger::{ReceivingTransferPhase, ReceivingTransferRecord};
use crate::executor_supervisor::ReceivingTransitionFailure;
use crate::{
    AttemptExecutionKey, AttemptRuntimeState, SourceTransferIntent, SourceTransferPreparation,
};

/// Retains the actual source Service and one live maintenance original.
///
/// The authenticated archive and checkpoint remain charged until explicit
/// physical retirement. A prepared source claim borrows this owner; bytes from
/// restart cannot create it or renew its operation.
pub struct GuardedSourceTransferOperation<'owner> {
    aliases: Option<GuardedMaintenanceAliases<'owner>>,
    source_owner: Option<GuardedServiceSource>,
    retirement: Option<crate::PreparedSourceRetirement>,
    source: Option<GuardedCampaignOwner>,
    offered: bool,
    completed: bool,
    terminal_failure_returned: bool,
}

/// Once-issued live source offer from the original actor's exact Paused CAS.
pub struct GuardedSourceTransferOffer<'source, 'owner> {
    operation: &'source GuardedSourceTransferOperation<'owner>,
    preparation: SourceTransferPreparation<'source>,
    release_attempted: bool,
    release: Option<DurableSourceRelease>,
}

pub(crate) struct GuardedReceivingReady {
    record: ReceivingTransferRecord,
}

impl GuardedReceivingReady {
    pub(crate) const fn record(&self) -> ReceivingTransferRecord {
        self.record
    }

    pub(crate) fn source_authorization<'original>(
        &self,
        source: &SourceTransferPreparation<'original>,
    ) -> Option<crate::SourceTransferReleaseAuthorization<'original>> {
        crate::SourceTransferReleaseAuthorization::from_stopped_receiver(source, self)
    }
}

struct DurableSourceRelease {
    record: ReceivingTransferRecord,
}

impl GuardedCampaignOwner {
    /// Retains an authenticated source original before installing its fence.
    ///
    /// # Errors
    /// Refuses another daemon/backend, insufficient actual Service resources,
    /// canceled or expired authentication, or an incomplete imported root.
    /// No source fence or destination execution authority is created here.
    pub fn prepare_source_transfer_operation<'owner>(
        &self,
        imported: AuthenticatedImportedCheckpoint<'owner>,
        cancellation: ExecutionCancellation,
    ) -> Result<GuardedSourceTransferOperation<'owner>, ReceivingExecutionPreparationError> {
        let (source_owner, aliases) = self.prepare_retained_maintenance(imported, cancellation)?;
        let operation = GuardedSourceTransferOperation {
            aliases: Some(aliases),
            source_owner: Some(source_owner),
            retirement: None,
            source: Some(self.clone()),
            offered: false,
            completed: false,
            terminal_failure_returned: false,
        };
        operation
            .aliases
            .as_ref()
            .and_then(GuardedMaintenanceAliases::maintenance)
            .ok_or(ReceivingExecutionPreparationError::Unavailable)?
            .check()
            .map_err(ReceivingExecutionPreparationError::Original)?;
        Ok(operation)
    }
}

impl<'owner> GuardedSourceTransferOperation<'owner> {
    /// Fences the exact authenticated paused source once on its sole writer.
    ///
    /// # Errors
    /// Refuses any reused live offer, different checkpoint, stale/active source,
    /// terminal original, competing declaration or uncertain persistence.
    /// The attempt is not reset after error; a committed-after-error fence can
    /// never silently produce another live offer.
    pub fn prepare<'source>(
        &'source mut self,
        key: AttemptExecutionKey,
        expected: AttemptRuntimeState,
        intent: SourceTransferIntent,
    ) -> Result<GuardedSourceTransferOffer<'source, 'owner>, GuardedTransferError> {
        if self.offered || self.completed {
            return Err(GuardedTransferError::Unavailable);
        }
        self.offered = true;
        let basis = self
            .aliases
            .as_ref()
            .and_then(GuardedMaintenanceAliases::basis)
            .ok_or(GuardedTransferError::Unavailable)?;
        if expected.checkpoint() != Some(basis.checkpoint) {
            return Err(GuardedTransferError::Binding);
        }
        let maintenance = self
            .aliases
            .as_ref()
            .and_then(GuardedMaintenanceAliases::maintenance)
            .ok_or(GuardedTransferError::Unavailable)?;
        maintenance.check()?;
        let owner = self
            .source
            .as_ref()
            .ok_or(GuardedTransferError::Unavailable)?;
        let preparation = owner.inner.actor.prepare_source_transfer(
            key,
            expected,
            intent,
            maintenance.original(),
        )??;
        maintenance.check()?;
        Ok(GuardedSourceTransferOffer {
            operation: self,
            preparation,
            release_attempted: false,
            release: None,
        })
    }

    /// Retires this source authentication Service after all live offers close.
    ///
    /// # Errors
    /// Refuses uncertain Service retirement or a failed final original cut.
    /// This does not delete a source fence or restore source resume permission.
    pub fn finish(&mut self) -> Result<(), ReceivingExecutionPreparationError> {
        if self.completed {
            return if self.terminal_failure_returned {
                Err(ReceivingExecutionPreparationError::HistoryAlreadyReturned)
            } else {
                Ok(())
            };
        }
        if let Some(aliases) = self.aliases.take() {
            aliases
                .return_to_main(None)
                .map_err(ReceivingExecutionPreparationError::Cleanup)?;
        }
        match finish_service_retirement(&mut self.source_owner, &mut self.retirement) {
            Ok(()) => self.completed = true,
            Err(ReceivingExecutionPreparationError::Terminal(history)) => {
                self.completed = true;
                self.terminal_failure_returned = true;
                self.source = None;
                return Err(ReceivingExecutionPreparationError::Terminal(history));
            }
            Err(first) => return Err(first),
        }
        self.source = None;
        Ok(())
    }
}

impl Drop for GuardedSourceTransferOperation<'_> {
    fn drop(&mut self) {
        // Its original no-World journal, not an absent Loop field, selects the
        // Main cleanup route after these actual aliases are durably delivered.
        drop(self.aliases.take());
        if let Some(source) = &self.source_owner {
            source
                .service_handle()
                .prepared_selector()
                .request_retirement();
        }
    }
}

impl GuardedSourceTransferOffer<'_, '_> {
    fn release(
        &mut self,
        ready: &GuardedReceivingReady,
    ) -> Result<&DurableSourceRelease, GuardedTransferError> {
        if self.release.is_none() {
            if self.release_attempted {
                return Err(GuardedTransferError::Unavailable);
            }
            let authorization = ready
                .source_authorization(&self.preparation)
                .ok_or(GuardedTransferError::Binding)?;
            let maintenance = self
                .operation
                .aliases
                .as_ref()
                .and_then(GuardedMaintenanceAliases::maintenance)
                .ok_or(GuardedTransferError::Unavailable)?;
            maintenance.check()?;
            self.release_attempted = true;
            self.operation
                .source
                .as_ref()
                .ok_or(GuardedTransferError::Unavailable)?
                .inner
                .actor
                .release_source_transfer(&self.preparation, authorization)??;
            maintenance.check()?;
            self.release = Some(DurableSourceRelease {
                record: ready.record,
            });
        }
        if self
            .release
            .as_ref()
            .is_some_and(|receipt| receipt.record != ready.record)
        {
            return Err(GuardedTransferError::Binding);
        }
        self.release
            .as_ref()
            .ok_or(GuardedTransferError::Unavailable)
    }
}

impl ReceivingExecutionPreparation<'_> {
    /// Durably binds readiness while retaining the actual stopped World.
    ///
    /// # Errors
    /// Refuses mismatched source/destination/checkpoint, an existing journal
    /// observation, original cancellation or uncertain persistence. A stored
    /// Ready row after error cannot reissue the live readiness capability.
    pub fn seal_readiness(
        &mut self,
        source: &GuardedSourceTransferOffer<'_, '_>,
        possession: crate::campaign_transfer::CampaignArchiveExecutionPossession,
    ) -> Result<(), GuardedTransferError> {
        if self.completed
            || self.journal.is_some()
            || self.ready.is_some()
            || self.lifecycle.is_none()
        {
            return Err(GuardedTransferError::Unavailable);
        }
        source
            .operation
            .aliases
            .as_ref()
            .and_then(GuardedMaintenanceAliases::maintenance)
            .ok_or(GuardedTransferError::Unavailable)?
            .check()?;
        let destination = self
            .destination
            .as_ref()
            .ok_or(GuardedTransferError::Unavailable)?;
        let basis = self
            .aliases
            .as_ref()
            .and_then(GuardedMaintenanceAliases::basis)
            .ok_or(GuardedTransferError::Unavailable)?;
        let intent = source
            .preparation
            .binding()
            .1
            .source_transfer()
            .ok_or(GuardedTransferError::Binding)?
            .intent();
        let source_owner = source
            .operation
            .source
            .as_ref()
            .ok_or(GuardedTransferError::Unavailable)?;
        if !possession.verify_binding(
            &source_owner.inner.repository.blob_backend(),
            &destination.inner.repository.blob_backend(),
            basis.archive,
            intent.namespace,
            intent.durable_placements,
        ) {
            return Err(GuardedTransferError::Binding);
        }
        let record = ReceivingTransferRecord::for_stopped_owner(
            &source.preparation,
            basis.archive,
            destination.inner.config.daemon_epoch,
            basis.checkpoint,
            &possession,
        )
        .ok_or(GuardedTransferError::Binding)?;
        // Keep the attempted binding before publication and every postcut.
        // It remains diagnostic custody on error, not a readiness capability.
        self.possession = Some(possession);
        self.journal = Some(record);
        self.verify_stopped_world()?;
        self.write_journal(None, record)?;
        self.verify_stopped_world()?;
        source
            .operation
            .aliases
            .as_ref()
            .and_then(GuardedMaintenanceAliases::maintenance)
            .ok_or(GuardedTransferError::Unavailable)?
            .check()?;
        self.ready = Some(GuardedReceivingReady { record });
        Ok(())
    }

    /// Releases the exact source then durably commits this stopped destination.
    ///
    /// Both live owners and originals remain retained. The source is fenced
    /// before the destination commit can persist. This local issuer neither
    /// authenticates a cross-host transport nor exposes executable World state.
    ///
    /// # Errors
    /// Refuses a different offer, missing live readiness, either original cut,
    /// source release uncertainty or destination journal failure. A failed
    /// destination commit keeps the entire World stopped and charged.
    pub fn commit_from_source(
        &mut self,
        source: &mut GuardedSourceTransferOffer<'_, '_>,
    ) -> Result<(), GuardedTransferError> {
        self.verify_stopped_world()?;
        let ready = self
            .ready
            .as_ref()
            .ok_or(GuardedTransferError::Unavailable)?;
        let expected = ready.record;
        self.aliases
            .as_ref()
            .and_then(GuardedMaintenanceAliases::maintenance)
            .ok_or(GuardedTransferError::Unavailable)?
            .check()?;
        let receipt = source.release(ready)?;
        if receipt.record != expected {
            return Err(GuardedTransferError::Binding);
        }
        let next = expected.committed().ok_or(GuardedTransferError::Binding)?;
        self.verify_stopped_world()?;
        self.write_journal(Some(expected), next)?;
        self.verify_stopped_world()?;
        source
            .operation
            .aliases
            .as_ref()
            .and_then(GuardedMaintenanceAliases::maintenance)
            .ok_or(GuardedTransferError::Unavailable)?
            .check()?;
        self.journal = Some(next);
        Ok(())
    }

    pub(super) fn abort_journal(&mut self) -> Result<(), GuardedTransferError> {
        let Some(record) = self.journal else {
            return Ok(());
        };
        if record.phase() != ReceivingTransferPhase::Ready {
            return Ok(());
        }
        let aborted = record.aborted().ok_or(GuardedTransferError::Binding)?;
        self.write_journal(Some(record), aborted)?;
        self.journal = Some(aborted);
        self.ready = None;
        Ok(())
    }

    fn verify_stopped_world(&mut self) -> Result<(), GuardedTransferError> {
        let maintenance = self
            .aliases
            .as_ref()
            .and_then(GuardedMaintenanceAliases::maintenance)
            .ok_or(GuardedTransferError::Unavailable)?;
        maintenance.check()?;
        self.lifecycle
            .as_mut()
            .ok_or(GuardedTransferError::Unavailable)?
            .verify_stopped(maintenance.original())
            .map_err(GuardedTransferError::Stopped)?;
        maintenance.check()?;
        Ok(())
    }

    fn write_journal(
        &self,
        expected: Option<ReceivingTransferRecord>,
        next: ReceivingTransferRecord,
    ) -> Result<(), GuardedTransferError> {
        let maintenance = self
            .aliases
            .as_ref()
            .and_then(GuardedMaintenanceAliases::maintenance)
            .ok_or(GuardedTransferError::Unavailable)?;
        self.destination
            .as_ref()
            .ok_or(GuardedTransferError::Unavailable)?
            .inner
            .actor
            .write_receiving_transfer(expected, next, &mut || maintenance.check())??;
        Ok(())
    }
}

/// Typed local transfer refusal preserving both original persistence causes.
#[derive(Debug, thiserror::Error)]
pub enum GuardedTransferError {
    /// Required live custody has closed or has already been consumed.
    #[error("guarded transfer custody is unavailable")]
    Unavailable,
    /// The full source/destination readiness binding differs.
    #[error("guarded transfer binding differs")]
    Binding,
    /// The actual source or destination original refused.
    #[error("guarded transfer original refused")]
    Original(#[from] HostSupervisionError),
    /// Actual stopped process ownership or native runstate refused.
    #[error("guarded transfer stopped World refused")]
    Stopped(#[source] crate::ProductionStoppedLifecycleError),
    /// The existing sole-writer actor refused its route.
    #[error("guarded transfer actor refused")]
    Route(#[from] crucible_api::host_operational::HostOperationalError),
    /// Source ledger persistence refused or remained uncertain.
    #[error("guarded transfer source fence refused")]
    Source(#[from] crate::SourceTransferFailure<crate::AssignmentLedgerError>),
    /// Reading the destination journal failed.
    #[error("guarded transfer receiving journal failed")]
    Journal(#[source] crate::AssignmentLedgerError),
    /// The journal key already names a different or terminal observation.
    #[error("guarded transfer receiving journal conflicts")]
    Conflict,
    /// Initiating persistence cause remains primary despite later observations.
    #[error("guarded transfer receiving persistence failed")]
    Persistence {
        /// Initiating durable write failure.
        #[source]
        source: crate::AssignmentLedgerError,
        /// The requested row was observed; this does not issue a live claim.
        observed: bool,
        /// Later lookup failure, if reconciliation could not complete.
        reconciliation: Option<crate::AssignmentLedgerError>,
        /// Later original refusal, without replacing the initiating cause.
        original: Option<HostSupervisionError>,
    },
}

impl From<ReceivingTransitionFailure> for GuardedTransferError {
    fn from(source: ReceivingTransitionFailure) -> Self {
        match source {
            ReceivingTransitionFailure::Original(source) => Self::Original(source),
            ReceivingTransitionFailure::Ledger(source) => Self::Journal(source),
            ReceivingTransitionFailure::Conflict => Self::Conflict,
            ReceivingTransitionFailure::Persistence {
                source,
                observed,
                reconciliation,
                original,
            } => Self::Persistence {
                source,
                observed,
                reconciliation,
                original,
            },
        }
    }
}
