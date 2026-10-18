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
        QemuAttemptProductionVmLifecycleError::PreparedSource(report) => report
            .with_first_error(prepared_source_first_class)
            .unwrap_or(SchedulerOperationalFailureClass::Terminal),
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
        | QemuAttemptProductionVmLifecycleError::SourceMainPreparation(_)
        | QemuAttemptProductionVmLifecycleError::SourceInstallRetained { .. }
        | QemuAttemptProductionVmLifecycleError::SourceCleanupHistory(_)
        | QemuAttemptProductionVmLifecycleError::SourceGenerationStorage(_)
        | QemuAttemptProductionVmLifecycleError::CheckpointRestore(_) => {
            SchedulerOperationalFailureClass::Terminal
        }
    }
}

fn prepared_source_first_class(
    first: &(dyn std::error::Error + 'static),
) -> SchedulerOperationalFailureClass {
    let Some(first) = first.downcast_ref::<QemuAttemptProductionVmLifecycleError>() else {
        // A native-only fallback is later cleanup history, not an initiating
        // request whose retry class can authorize another attempt.
        return SchedulerOperationalFailureClass::Terminal;
    };
    if matches!(
        first,
        QemuAttemptProductionVmLifecycleError::PreparedSource(_)
    ) {
        // Raw Pending history must never contain its own protected report.
        // Refuse an invalid nested report without recursively locking Main.
        return SchedulerOperationalFailureClass::Terminal;
    }
    production_lifecycle_failure_class(first)
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
        let source = crucible_engine::owned_decode::DecodeAdmissionError::new(
            std::io::Error::other("explicit fixture metadata refusal"),
        );
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
                .downcast_ref::<crucible_engine::owned_decode::DecodeAdmissionError>()
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
    fn retained_cleanup_keeps_factory_refusal_terminal_policy() {
        for error in [
            LifecycleApiError::CleanupRetained,
            LifecycleApiError::LoopFactory {
                message: String::from("component cleanup refusal"),
            },
        ] {
            assert!(matches!(
                classify_production_lifecycle_failure(
                    QemuAttemptProductionVmLifecycleError::Lifecycle(error),
                ),
                AttemptWorkerFailure::Terminal(_)
            ));
        }
    }

    #[test]
    fn single_begin_reports_preserve_unavailability_and_cancellation() {
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
    fn retained_member_cleanup_stays_terminal_in_both_installation_paths() {
        for begin in [false, true] {
            let source = QemuVmRealizationError::CleanupRetained {
                operation: "finish hot-fork World member",
            };
            let error = if begin {
                QemuAttemptProductionVmLifecycleError::ResourceBeginInstallation(source.into())
            } else {
                QemuAttemptProductionVmLifecycleError::ResourceInstallation(source)
            };
            assert!(matches!(
                production_lifecycle_failure_class(&error),
                SchedulerOperationalFailureClass::Terminal
            ));
        }
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

#[cfg(test)]
mod protected_first_tests {
    use super::*;

    #[test]
    fn protected_first_projection_preserves_actual_request_retry_and_cancel_classes() {
        let retry = QemuAttemptProductionVmLifecycleError::ModelCopy(Box::new(
            std::io::Error::other("actual model copy refusal"),
        ));
        assert_eq!(
            prepared_source_first_class(&retry),
            SchedulerOperationalFailureClass::Retryable
        );

        let canceled = QemuAttemptProductionVmLifecycleError::CheckpointRestore(Box::new(
            ProductionAttemptCheckpointRestoreError::Canceled,
        ));
        assert_eq!(
            prepared_source_first_class(&canceled),
            SchedulerOperationalFailureClass::Canceled
        );

        // Actual report constructors transport typed status only. They issue
        // no World and establish no physical quarantine or return evidence.
        let failure = crate::crucible_qemu_session::QemuAttemptResourceGuardBeginFailure::before_checkpoint_claim(
            QemuVmRealizationError::Canceled { operation: "component raw begin" },
            None,
        );
        let (report, _) = failure.into_parts();
        let canceled = QemuAttemptProductionVmLifecycleError::ResourceBeginInstallation(report);
        assert_eq!(
            prepared_source_first_class(&canceled),
            SchedulerOperationalFailureClass::Canceled
        );

        let failure = crate::crucible_qemu_session::QemuAttemptResourceGuardBeginFailure::rollback(
            QemuVmRealizationError::Canceled {
                operation: "component raw begin",
            },
            crate::QemuAttemptResourceGuardCleanupFailure::quarantined(
                QemuVmRealizationError::Canceled {
                    operation: "component raw rollback",
                },
            ),
        );
        let (report, _) = failure.into_parts();
        let quarantined = QemuAttemptProductionVmLifecycleError::ResourceBeginInstallation(report);
        assert_eq!(
            prepared_source_first_class(&quarantined),
            SchedulerOperationalFailureClass::Terminal
        );
    }

    #[test]
    fn cleanup_or_foreign_projection_cannot_bless_a_new_request() {
        let cleanup = QemuVmRealizationError::ExecutorUnavailable {
            operation: "later cleanup only",
            message: String::from("same native cleanup leaf"),
        };
        let QemuVmRealizationError::ExecutorUnavailable { message, .. } = &cleanup else {
            panic!("unexpected fixture variant");
        };
        let pointer = message.as_ptr();
        assert_eq!(
            prepared_source_first_class(&cleanup),
            SchedulerOperationalFailureClass::Terminal
        );
        let QemuVmRealizationError::ExecutorUnavailable { message, .. } = &cleanup else {
            panic!("cleanup cause was replaced");
        };
        assert_eq!(message.as_ptr(), pointer);
        let foreign = std::io::Error::other("unrecognized projection");
        assert_eq!(
            prepared_source_first_class(&foreign),
            SchedulerOperationalFailureClass::Terminal
        );
    }
}
