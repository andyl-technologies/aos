//! Concrete failures retained by the admitted campaign execution route.
//!
//! Linear prepared tokens can be movable without permitting concurrent access.
//! Each diagnostic mutex retains its concrete source and original cleanup
//! custody; no conversion erases the source into a general error object.

use std::error::Error;
use std::fmt;
use std::sync::Mutex;

#[derive(Debug)]
pub(in crate::qemu_campaign_lifecycle::campaign_run) struct RetainedFailure<T>(Mutex<T>);

/// Refuses access when a previous diagnostic callback panicked.
#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("retained failure diagnostic access is unavailable")]
pub(in crate::qemu_campaign_lifecycle::campaign_run) struct RetainedFailureAccessError;

impl<T> RetainedFailure<T> {
    /// Borrows the original concrete failure while its custody remains locked.
    ///
    /// The callback cannot return a reference into the failure. Standard error
    /// traversal ends at this wrapper; typed classification uses this callback.
    pub(in crate::qemu_campaign_lifecycle::campaign_run) fn with_source<R>(
        &self,
        inspect: impl FnOnce(&T) -> R,
    ) -> Result<R, RetainedFailureAccessError> {
        let source = self.0.lock().map_err(|_| RetainedFailureAccessError)?;
        Ok(inspect(&source))
    }
}

impl<T: fmt::Display> fmt::Display for RetainedFailure<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.with_source(|source| fmt::Display::fmt(source, formatter)) {
            Ok(result) => result,
            Err(error) => fmt::Display::fmt(&error, formatter),
        }
    }
}

impl<T: Error> Error for RetainedFailure<T> {}

#[derive(Debug)]
pub(in crate::qemu_campaign_lifecycle::campaign_run) enum AdmittedCampaignError<E> {
    Operational(RetainedFailure<crucible_api::host_operational::HostOperationalError>),
    Actor(RetainedFailure<crate::LocalExecutorError<crate::AssignmentLedgerError>>),
    Io(RetainedFailure<std::io::Error>),
    CompletedSource(
        RetainedFailure<crate::packaged_qemu_executor::guarded::CompletedReproductionError>,
    ),
    Service(RetainedFailure<crate::PackagedQemuExecutorError>),
    Supervision(RetainedFailure<crucible_linux_resource::host_supervision::HostSupervisionError>),
    Preparation(
        RetainedFailure<
            crate::AttemptResultPreparationError<crate::RepositoryAttemptWorkerError<E>>,
        >,
    ),
    CaptureBinding(RetainedFailure<crate::executor_worker::SemanticReplayCaptureBindingError>),
    Journal(RetainedFailure<crate::PreparedResultJournalError>),
    PreparedHandoff(RetainedFailure<crate::executor_worker::AdmittedPreparedResultFailure>),
    Publication(RetainedFailure<crate::AttemptResultPublicationError>),
    Reconciliation(
        RetainedFailure<
            crate::AttemptWorkerReconcileError<
                crate::RepositoryAttemptWorkerError<E>,
                crate::LocalExecutorError<crate::AssignmentLedgerError>,
            >,
        >,
    ),
    CheckpointStaging(
        RetainedFailure<
            crate::CheckpointResultStagingError<
                crate::LocalExecutorError<crate::AssignmentLedgerError>,
            >,
        >,
    ),
    CheckpointPublication(RetainedFailure<crate::CheckpointResultPublicationError>),
    CheckpointReconciliation(
        RetainedFailure<
            crate::CheckpointResultReconcileError<
                crate::LocalExecutorError<crate::AssignmentLedgerError>,
            >,
        >,
    ),
    ExactInventory(
        RetainedFailure<crate::automatic_finding_runner::FindingExactCandidateInventoryError>,
    ),
}

impl<E: fmt::Display> fmt::Display for AdmittedCampaignError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Operational(source) => fmt::Display::fmt(source, formatter),
            Self::Actor(source) => fmt::Display::fmt(source, formatter),
            Self::Io(source) => fmt::Display::fmt(source, formatter),
            Self::CompletedSource(source) => fmt::Display::fmt(source, formatter),
            Self::Service(source) => fmt::Display::fmt(source, formatter),
            Self::Supervision(source) => fmt::Display::fmt(source, formatter),
            Self::Preparation(source) => fmt::Display::fmt(source, formatter),
            Self::CaptureBinding(source) => fmt::Display::fmt(source, formatter),
            Self::Journal(source) => fmt::Display::fmt(source, formatter),
            Self::PreparedHandoff(source) => fmt::Display::fmt(source, formatter),
            Self::Publication(source) => fmt::Display::fmt(source, formatter),
            Self::Reconciliation(source) => fmt::Display::fmt(source, formatter),
            Self::CheckpointStaging(source) => fmt::Display::fmt(source, formatter),
            Self::CheckpointPublication(source) => fmt::Display::fmt(source, formatter),
            Self::CheckpointReconciliation(source) => fmt::Display::fmt(source, formatter),
            Self::ExactInventory(source) => fmt::Display::fmt(source, formatter),
        }
    }
}

impl<E: Error + 'static> Error for AdmittedCampaignError<E> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Operational(source) => Some(source),
            Self::Actor(source) => Some(source),
            Self::Io(source) => Some(source),
            Self::CompletedSource(source) => Some(source),
            Self::Service(source) => Some(source),
            Self::Supervision(source) => Some(source),
            Self::Preparation(source) => Some(source),
            Self::CaptureBinding(source) => Some(source),
            Self::Journal(source) => Some(source),
            Self::PreparedHandoff(source) => Some(source),
            Self::Publication(source) => Some(source),
            Self::Reconciliation(source) => Some(source),
            Self::CheckpointStaging(source) => Some(source),
            Self::CheckpointPublication(source) => Some(source),
            Self::CheckpointReconciliation(source) => Some(source),
            Self::ExactInventory(source) => Some(source),
        }
    }
}

impl<E> From<crucible_api::host_operational::HostOperationalError> for AdmittedCampaignError<E> {
    fn from(source: crucible_api::host_operational::HostOperationalError) -> Self {
        Self::Operational(RetainedFailure(Mutex::new(source)))
    }
}

impl<E> From<crate::LocalExecutorError<crate::AssignmentLedgerError>> for AdmittedCampaignError<E> {
    fn from(source: crate::LocalExecutorError<crate::AssignmentLedgerError>) -> Self {
        Self::Actor(RetainedFailure(Mutex::new(source)))
    }
}

impl<E> From<std::io::Error> for AdmittedCampaignError<E> {
    fn from(source: std::io::Error) -> Self {
        Self::Io(RetainedFailure(Mutex::new(source)))
    }
}

impl<E> From<crate::packaged_qemu_executor::guarded::CompletedReproductionError>
    for AdmittedCampaignError<E>
{
    fn from(source: crate::packaged_qemu_executor::guarded::CompletedReproductionError) -> Self {
        Self::CompletedSource(RetainedFailure(Mutex::new(source)))
    }
}

impl<E> From<crate::PackagedQemuExecutorError> for AdmittedCampaignError<E> {
    fn from(source: crate::PackagedQemuExecutorError) -> Self {
        Self::Service(RetainedFailure(Mutex::new(source)))
    }
}

impl<E> From<crucible_linux_resource::host_supervision::HostSupervisionError>
    for AdmittedCampaignError<E>
{
    fn from(source: crucible_linux_resource::host_supervision::HostSupervisionError) -> Self {
        Self::Supervision(RetainedFailure(Mutex::new(source)))
    }
}

impl<E> From<crate::AttemptResultPreparationError<crate::RepositoryAttemptWorkerError<E>>>
    for AdmittedCampaignError<E>
{
    fn from(
        source: crate::AttemptResultPreparationError<crate::RepositoryAttemptWorkerError<E>>,
    ) -> Self {
        Self::Preparation(RetainedFailure(Mutex::new(source)))
    }
}

impl<E> From<crate::executor_worker::SemanticReplayCaptureBindingError>
    for AdmittedCampaignError<E>
{
    fn from(source: crate::executor_worker::SemanticReplayCaptureBindingError) -> Self {
        Self::CaptureBinding(RetainedFailure(Mutex::new(source)))
    }
}

impl<E> From<crate::PreparedResultJournalError> for AdmittedCampaignError<E> {
    fn from(source: crate::PreparedResultJournalError) -> Self {
        Self::Journal(RetainedFailure(Mutex::new(source)))
    }
}

impl<E> From<crate::executor_worker::AdmittedPreparedResultFailure> for AdmittedCampaignError<E> {
    fn from(source: crate::executor_worker::AdmittedPreparedResultFailure) -> Self {
        Self::PreparedHandoff(RetainedFailure(Mutex::new(source)))
    }
}

impl<E> From<crate::AttemptResultPublicationError> for AdmittedCampaignError<E> {
    fn from(source: crate::AttemptResultPublicationError) -> Self {
        Self::Publication(RetainedFailure(Mutex::new(source)))
    }
}

impl<E>
    From<
        crate::AttemptWorkerReconcileError<
            crate::RepositoryAttemptWorkerError<E>,
            crate::LocalExecutorError<crate::AssignmentLedgerError>,
        >,
    > for AdmittedCampaignError<E>
{
    fn from(
        source: crate::AttemptWorkerReconcileError<
            crate::RepositoryAttemptWorkerError<E>,
            crate::LocalExecutorError<crate::AssignmentLedgerError>,
        >,
    ) -> Self {
        Self::Reconciliation(RetainedFailure(Mutex::new(source)))
    }
}

impl<E>
    From<
        crate::CheckpointResultStagingError<
            crate::LocalExecutorError<crate::AssignmentLedgerError>,
        >,
    > for AdmittedCampaignError<E>
{
    fn from(
        source: crate::CheckpointResultStagingError<
            crate::LocalExecutorError<crate::AssignmentLedgerError>,
        >,
    ) -> Self {
        Self::CheckpointStaging(RetainedFailure(Mutex::new(source)))
    }
}

impl<E> From<crate::CheckpointResultPublicationError> for AdmittedCampaignError<E> {
    fn from(source: crate::CheckpointResultPublicationError) -> Self {
        Self::CheckpointPublication(RetainedFailure(Mutex::new(source)))
    }
}

impl<E>
    From<
        crate::CheckpointResultReconcileError<
            crate::LocalExecutorError<crate::AssignmentLedgerError>,
        >,
    > for AdmittedCampaignError<E>
{
    fn from(
        source: crate::CheckpointResultReconcileError<
            crate::LocalExecutorError<crate::AssignmentLedgerError>,
        >,
    ) -> Self {
        Self::CheckpointReconciliation(RetainedFailure(Mutex::new(source)))
    }
}

impl<E> From<crate::automatic_finding_runner::FindingExactCandidateInventoryError>
    for AdmittedCampaignError<E>
{
    fn from(source: crate::automatic_finding_runner::FindingExactCandidateInventoryError) -> Self {
        Self::ExactInventory(RetainedFailure(Mutex::new(source)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible_linux_resource::host_supervision::{
        HostOperationBudgets, HostOperationClass, HostOperationState, HostOperationSupervisor,
        HostSupervisionError,
    };

    #[test]
    fn retained_supervision_failure_preserves_original_cancellation() -> Result<(), Box<dyn Error>>
    {
        let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None)?;
        let operation = supervisor.begin(HostOperationClass::PageIn)?;
        supervisor.cancel()?;
        let original = operation
            .wait_slice()
            .err()
            .ok_or("cancelled operation did not refuse")?;
        let retained = AdmittedCampaignError::<std::io::Error>::from(original);

        let AdmittedCampaignError::Supervision(source) = &retained else {
            return Err("supervision failure changed variant".into());
        };
        source.with_source(|actual| {
            assert_eq!(actual, &original);
            assert!(matches!(
                actual,
                HostSupervisionError::Terminal {
                    state: HostOperationState::Canceled,
                }
            ));
        })?;
        assert!(source.source().is_none());
        assert!(retained.source().is_some());
        Ok(())
    }
}
