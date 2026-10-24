//! Binds lifecycle retry classification to typed first causes and quarantine.
//!
//! These pure policy projections do not schedule an attempt or issue cleanup,
//! Main, Source or physical-return authority. Independent owner contracts remain
//! necessary at every caller that actually enters another operation.

use super::{Companion, Contract};

const CLASSIFIER: &str = r###"pub(crate) fn classify_production_lifecycle_failure(
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
    first: crate::LifecycleFailureRef<'_>,
) -> SchedulerOperationalFailureClass {
    let crate::LifecycleFailureRef::Lifecycle(first) = first else {
        // Later cleanup history cannot authorize another initiating attempt.
        return SchedulerOperationalFailureClass::Terminal;
    };
    if matches!(
        first,
        QemuAttemptProductionVmLifecycleError::PreparedSource(_)
    ) {
        // Refuse a nested report without recursively locking its same Main.
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
}"###;

const CONTROLS: &str = r###"#[cfg(test)]
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
            prepared_source_first_class(crate::LifecycleFailureRef::Lifecycle(&retry)),
            SchedulerOperationalFailureClass::Retryable
        );

        let canceled = QemuAttemptProductionVmLifecycleError::CheckpointRestore(Box::new(
            ProductionAttemptCheckpointRestoreError::Canceled,
        ));
        assert_eq!(
            prepared_source_first_class(crate::LifecycleFailureRef::Lifecycle(&canceled)),
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
            prepared_source_first_class(crate::LifecycleFailureRef::Lifecycle(&canceled)),
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
            prepared_source_first_class(crate::LifecycleFailureRef::Lifecycle(&quarantined)),
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
            prepared_source_first_class(crate::LifecycleFailureRef::Realization(&cleanup)),
            SchedulerOperationalFailureClass::Terminal
        );
        let QemuVmRealizationError::ExecutorUnavailable { message, .. } = &cleanup else {
            panic!("cleanup cause was replaced");
        };
        assert_eq!(message.as_ptr(), pointer);
        let foreign = std::io::Error::other("unrecognized projection");
        assert_eq!(
            prepared_source_first_class(crate::LifecycleFailureRef::Io(&foreign)),
            SchedulerOperationalFailureClass::Terminal
        );
    }
}"###;

const PUBLIC_FIRST: &str = r###"    pub fn with_first_error<R>(
        &self,
        apply: impl FnOnce(LifecycleFailureRef<'_>) -> R,
    ) -> Option<R> {
        let mut apply = Some(apply);
        if let Some(result) = self
            .retirement
            .with_first_error(|first| apply.take().map(|apply| apply(first)))
        {
            return result;
        }
        self.access
            .as_ref()
            .and_then(|first| apply.take().map(|apply| apply(Failure::Role(first))))
    }"###;

const PROTECTED_FIRST: &str = r###"    fn with_first_error<R>(&self, apply: impl FnOnce(LifecycleFailureRef<'_>) -> R) -> Option<R> {
        let queue = self.key.queue.upgrade()?;
        let slot = queue.slots.get(self.key.index)?;
        if slot.epoch.load(Ordering::Acquire) != self.key.epoch {
            return None;
        }
        let service = slot.service.try_lock().ok()?;
        if slot.is(CleanupPhase::TerminalOwned) || slot.is(CleanupPhase::TerminalDisposing) {
            return None;
        }
        if service.epoch == self.key.epoch
            && let Some(first) = service.start.as_ref().and_then(|start| start.first())
        {
            return Some(apply(Failure::Service(first)));
        }
        if service.epoch == self.key.epoch
            && let Some(first) = service
                .start
                .as_ref()
                .and_then(|start| start.adopted_semantic_shutdown_failure())
        {
            return Some(apply(Failure::Scheduler(first)));
        }
        drop(service);
        let prepared = slot.prepared.try_lock().ok()?;
        if slot.is(CleanupPhase::TerminalOwned) || slot.is(CleanupPhase::TerminalDisposing) {
            return None;
        }
        if prepared.epoch == self.key.epoch
            && let (Some(owner), Some(project)) = (&prepared.owner, prepared.projection)
            && let Some(first) = project(owner.as_ref())
        {
            return Some(apply(first));
        }
        if prepared.epoch == self.key.epoch
            && let Some(first) = &prepared.terminal_access
        {
            return Some(apply(Failure::Role(first)));
        }
        drop(prepared);
        let service = slot.service.try_lock().ok()?;
        if service.epoch != self.key.epoch
            || slot.is(CleanupPhase::TerminalOwned)
            || slot.is(CleanupPhase::TerminalDisposing)
        {
            return None;
        }
        service
            .start
            .as_ref()
            .and_then(terminal::first_service_tail_failure)
            .or_else(|| {
                service
                    .return_body
                    .as_ref()
                    .and_then(|body| body.first_failure())
            })
            .map(apply)
    }"###;

const BEGIN_FIRST: &str = r###"    pub fn first_error(&self) -> &QemuVmRealizationError {
        &self.first
    }"###;

const BEGIN_QUARANTINE: &str = r###"    pub fn was_quarantined(&self) -> bool {
        self.cleanup
            .as_ref()
            .is_some_and(|cleanup| cleanup.was_quarantined())
    }"###;

const CLEANUP_QUARANTINE: &str = r###"    pub const fn was_quarantined(&self) -> bool {
        self.quarantined
    }"###;

pub(super) const CONTRACTS: &[Contract] = &[Contract {
    package: "crucible-daemon",
    target: "src/qemu_campaign_lifecycle/failure_classification",
    required: &[CLASSIFIER, CONTROLS],
    expressions: &[(CLASSIFIER, 1), (CONTROLS, 1)],
    companions: &[
        Companion {
            path: "crates/crucible/crucible-daemon/src/lifecycle_cleanup/prepared_retirement.rs",
            required: &[PUBLIC_FIRST, PROTECTED_FIRST],
            counts: &[(PUBLIC_FIRST, 1), (PROTECTED_FIRST, 1)],
        },
        Companion {
            path: "crates/crucible/crucible-daemon/src/crucible_qemu_session/resource_begin.rs",
            required: &[BEGIN_FIRST, BEGIN_QUARANTINE, CLEANUP_QUARANTINE],
            counts: &[
                (BEGIN_FIRST, 1),
                (BEGIN_QUARANTINE, 1),
                (CLEANUP_QUARANTINE, 1),
            ],
        },
    ],
}];

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::{mask_with_companions, read_companions};

    fn has_retry(code: &str) -> bool {
        crate::flaky_escape_failures("unreviewed", "unreviewed", code)
            .iter()
            .any(|finding| finding.contains("`retry`"))
    }

    fn source(contract: &Contract) -> Result<String, std::io::Error> {
        let root = crate::workspace_root();
        let path = crate::workspace::package_path(&root.join("crates"), contract.package)
            .join(format!("{}.rs", contract.target));
        Ok(crate::scrub_comments_and_strings(&std::fs::read_to_string(
            path,
        )?))
    }

    #[test]
    fn lifecycle_classification_requires_protected_first_and_quarantine_owners()
    -> Result<(), Box<dyn std::error::Error>> {
        for contract in CONTRACTS {
            let code = source(contract)?;
            let companions = read_companions(contract)?;

            assert!(has_retry(&code));
            assert!(!has_retry(&mask_with_companions(
                contract,
                &code,
                &companions
            )));
            let extra = format!("{code}\nfn unrelated_retry() {{ loop {{ retry(); }} }}");
            assert!(has_retry(&mask_with_companions(
                contract,
                &extra,
                &companions
            )));

            for (index, binding) in contract.companions.iter().enumerate() {
                for required in binding.required {
                    let mut changed = companions.clone();
                    assert!(changed[index].contains(required));
                    changed[index] = changed[index].replacen(required, "foreign();", 1);
                    assert!(has_retry(&mask_with_companions(contract, &code, &changed)));
                }
            }
        }
        Ok(())
    }

    #[test]
    fn lifecycle_classification_rejects_changed_status_and_erased_first_observations()
    -> Result<(), Box<dyn std::error::Error>> {
        let contract = &CONTRACTS[0];
        let code = super::super::compact_code(&source(contract)?);
        let companions = read_companions(contract)?;

        for (before, after) in [
            (
                "SchedulerOperationalFailureClass::Retryable=>AttemptWorkerFailure::Retryable(error)",
                "SchedulerOperationalFailureClass::Retryable=>AttemptWorkerFailure::Terminal(error)",
            ),
            (
                "ifreport.was_quarantined(){",
                "if!report.was_quarantined(){",
            ),
            (
                ".with_first_error(prepared_source_first_class)",
                ".with_first_error(|_|SchedulerOperationalFailureClass::Retryable)",
            ),
            (
                "first,QemuAttemptProductionVmLifecycleError::PreparedSource(_)",
                "first,QemuAttemptProductionVmLifecycleError::ModelCopy(_)",
            ),
            (
                "resource_installation_failure_class(report.first_error())",
                "SchedulerOperationalFailureClass::Retryable",
            ),
            (
                "SchedulerOperationalFailureClass::Terminal);",
                "SchedulerOperationalFailureClass::Retryable);",
            ),
            (
                "assert_eq!(message.as_ptr(),pointer);",
                "assert_ne!(message.as_ptr(),pointer);",
            ),
        ] {
            let before = super::super::compact_code(before);
            let after = super::super::compact_code(after);
            assert!(
                code.contains(&before),
                "missing actual lifecycle cut: {before}"
            );
            let owner = contract
                .required
                .iter()
                .find_map(|required| {
                    let required =
                        super::super::compact_code(&crate::scrub_comments_and_strings(required));
                    required.contains(&before).then_some(required)
                })
                .unwrap_or_else(|| panic!("missing reviewed owner for cut: {before}"));
            let changed = code.replacen(&owner, &owner.replacen(&before, &after, 1), 1);
            assert!(
                has_retry(&mask_with_companions(contract, &changed, &companions)),
                "changed lifecycle class was accepted: {before}"
            );
        }
        Ok(())
    }
}
