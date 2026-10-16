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
        QemuAttemptProductionVmLifecycleError::ResourceBeginInstallation(report) => {
            if report.was_quarantined() {
                return SchedulerOperationalFailureClass::Terminal;
            }
            resource_installation_failure_class(report.first_error())
        }
        QemuAttemptProductionVmLifecycleError::ModelCopy(_) => {
            SchedulerOperationalFailureClass::Retryable
        }
        QemuAttemptProductionVmLifecycleError::ResourceInstallation(error) => {
            resource_installation_failure_class(error)
        }
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
        | QemuAttemptProductionVmLifecycleError::ResourceContractMismatch
        | QemuAttemptProductionVmLifecycleError::ResourceContractCleanup(_)
        | QemuAttemptProductionVmLifecycleError::Lifecycle(_)
        | QemuAttemptProductionVmLifecycleError::SourceInstallRetained { .. }
        | QemuAttemptProductionVmLifecycleError::SourceCleanupHistory(_)
        | QemuAttemptProductionVmLifecycleError::SourceGenerationStorage(_)
        | QemuAttemptProductionVmLifecycleError::CheckpointRestore(_) => {
            SchedulerOperationalFailureClass::Terminal
        }
    }
}

fn resource_installation_failure_class(
    error: &QemuVmRealizationError,
) -> SchedulerOperationalFailureClass {
    match error {
        QemuVmRealizationError::ExecutorUnavailable { .. } => {
            SchedulerOperationalFailureClass::Retryable
        }
        QemuVmRealizationError::Canceled { .. } => SchedulerOperationalFailureClass::Canceled,
        #[cfg(target_os = "linux")]
        QemuVmRealizationError::TargetDispatcherRetirement { source }
            if source.dispatcher_error().is_some() && source.is_retryable() =>
        {
            // Source installation historically retries dispatcher I/O/namespace
            // failures, but its pool-only ModelCopy category remains terminal.
            SchedulerOperationalFailureClass::Retryable
        }
        _ => SchedulerOperationalFailureClass::Terminal,
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

    #[test]
    fn typed_begin_rollback_history_is_terminal_without_replacing_canceled_first() {
        let first = QemuVmRealizationError::Canceled {
            operation: "component initiating cancellation",
        };
        let cleanup = QemuVmRealizationError::ExecutorUnavailable {
            operation: "component rollback",
            message: String::from("actual independent refusal"),
        };
        let failure = crate::crucible_qemu_session::QemuAttemptResourceGuardBeginFailure::rollback(
            first,
            crate::crucible_qemu_session::QemuAttemptResourceGuardCleanupFailure::quarantined(
                cleanup,
            ),
        );
        let (report, _) = failure.into_parts();
        let failure = classify_production_lifecycle_failure(
            QemuAttemptProductionVmLifecycleError::ResourceBeginInstallation(report),
        );

        let AttemptWorkerFailure::Terminal(
            QemuAttemptProductionVmLifecycleError::ResourceBeginInstallation(report),
        ) = failure
        else {
            panic!("quarantine cannot become cancel success or an ordinary retry");
        };
        assert!(matches!(
            report.first_error(),
            QemuVmRealizationError::Canceled {
                operation: "component initiating cancellation"
            }
        ));
        assert!(matches!(
            report.cleanup_error(),
            Some(QemuVmRealizationError::ExecutorUnavailable {
                operation: "component rollback",
                ..
            })
        ));
    }

    #[test]
    fn typed_single_begin_reports_keep_existing_retry_and_cancel_classes() {
        let unavailable = QemuVmRealizationError::ExecutorUnavailable {
            operation: "component admission",
            message: String::from("temporarily unavailable"),
        };
        let canceled = QemuVmRealizationError::Canceled {
            operation: "component cancellation",
        };

        assert!(matches!(
            classify_production_lifecycle_failure(
                QemuAttemptProductionVmLifecycleError::ResourceBeginInstallation(
                    unavailable.into()
                ),
            ),
            AttemptWorkerFailure::Retryable(_)
        ));
        assert!(matches!(
            classify_production_lifecycle_failure(
                QemuAttemptProductionVmLifecycleError::ResourceBeginInstallation(canceled.into()),
            ),
            AttemptWorkerFailure::Canceled(_)
        ));
    }

    #[test]
    fn source_resource_model_copy_stays_terminal_in_both_installation_paths() {
        for begin in [false, true] {
            let source = QemuVmRealizationError::ModelCopy {
                source: Box::new(std::io::Error::other("actual model-copy refusal")),
            };
            let error = if begin {
                QemuAttemptProductionVmLifecycleError::ResourceBeginInstallation(source.into())
            } else {
                QemuAttemptProductionVmLifecycleError::ResourceInstallation(source)
            };

            assert!(matches!(
                classify_production_lifecycle_failure(error),
                AttemptWorkerFailure::Terminal(_)
            ));
        }
    }
}
