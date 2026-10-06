//! Classification of production lifecycle failures for executor retry policy.

use super::*;

pub(crate) fn classify_production_lifecycle_failure(
    error: QemuAttemptProductionVmLifecycleError,
) -> AttemptWorkerFailure<QemuAttemptProductionVmLifecycleError> {
    match production_lifecycle_failure_class(&error) {
        SchedulerOperationalFailureClass::Retryable => AttemptWorkerFailure::Retryable(error),
        SchedulerOperationalFailureClass::Canceled => AttemptWorkerFailure::Canceled(error),
        SchedulerOperationalFailureClass::Terminal => AttemptWorkerFailure::Terminal(error),
    }
}

pub(crate) fn production_lifecycle_failure_class(
    error: &QemuAttemptProductionVmLifecycleError,
) -> SchedulerOperationalFailureClass {
    if let QemuAttemptProductionVmLifecycleError::CheckpointRestore(source) = error {
        let Some(source) = source.downcast_ref::<ProductionAttemptCheckpointRestoreError>() else {
            return SchedulerOperationalFailureClass::Terminal;
        };

        return match source {
            ProductionAttemptCheckpointRestoreError::Canceled => {
                SchedulerOperationalFailureClass::Canceled
            }
            ProductionAttemptCheckpointRestoreError::Checkpoint(
                ExactCheckpointStoreError::Store(
                    StoreError::NotFound { .. }
                    | StoreError::Unavailable
                    | StoreError::Io { .. }
                    | StoreError::StreamIo { .. },
                ),
            ) => SchedulerOperationalFailureClass::Retryable,
            _ => SchedulerOperationalFailureClass::Terminal,
        };
    }

    match error {
        QemuAttemptProductionVmLifecycleError::ModelCopy(_) => {
            SchedulerOperationalFailureClass::Retryable
        }
        QemuAttemptProductionVmLifecycleError::ResourceInstallation(
            QemuVmRealizationError::ExecutorUnavailable { .. },
        ) => SchedulerOperationalFailureClass::Retryable,
        QemuAttemptProductionVmLifecycleError::ResourceInstallation(
            QemuVmRealizationError::Canceled { .. },
        ) => SchedulerOperationalFailureClass::Canceled,
        QemuAttemptProductionVmLifecycleError::ResumeCheckpointUnsupported(_)
        | QemuAttemptProductionVmLifecycleError::ScenarioIdentityMismatch
        | QemuAttemptProductionVmLifecycleError::InvalidNodeCount(_)
        | QemuAttemptProductionVmLifecycleError::ResourceRefusal(_)
        | QemuAttemptProductionVmLifecycleError::HostRamAdmission(_)
        | QemuAttemptProductionVmLifecycleError::HostWatchdogExpired
        | QemuAttemptProductionVmLifecycleError::InvalidResumeBoundary
        | QemuAttemptProductionVmLifecycleError::InvalidAppRandomBranchReplay(_)
        | QemuAttemptProductionVmLifecycleError::InvalidNetworkBranchReplay(_)
        | QemuAttemptProductionVmLifecycleError::InvalidSignalFaultBranchReplay(_)
        | QemuAttemptProductionVmLifecycleError::InvalidContinuationInput
        | QemuAttemptProductionVmLifecycleError::ResourceInstallation(_)
        | QemuAttemptProductionVmLifecycleError::ResourceContractMismatch
        | QemuAttemptProductionVmLifecycleError::ResourceContractCleanup(_)
        | QemuAttemptProductionVmLifecycleError::Lifecycle(_)
        | QemuAttemptProductionVmLifecycleError::CheckpointRestore(_) => {
            SchedulerOperationalFailureClass::Terminal
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn admitted_model_copy_refusal_remains_typed_operational_failure() {
        let source = crucible::owned_decode::DecodeAdmissionError::new(std::io::Error::other(
            "explicit fixture metadata refusal",
        ));
        let error = QemuAttemptProductionVmLifecycleError::ModelCopy(Box::new(source));
        let failure = classify_production_lifecycle_failure(error);
        let AttemptWorkerFailure::Retryable(error) = failure else {
            panic!("metadata exhaustion must remain infrastructure failure");
        };
        let source = error
            .source()
            .unwrap_or_else(|| panic!("typed cause is retained"));
        assert!(
            source
                .downcast_ref::<crucible::owned_decode::DecodeAdmissionError>()
                .is_some()
        );
        assert!(
            source
                .source()
                .and_then(|source| source.downcast_ref::<std::io::Error>())
                .is_some()
        );
    }
}
