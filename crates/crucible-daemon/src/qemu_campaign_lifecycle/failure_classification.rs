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
        | QemuAttemptProductionVmLifecycleError::InvalidResumeBoundary
        | QemuAttemptProductionVmLifecycleError::InvalidAppRandomBranchReplay(_)
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
