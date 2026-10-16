//! Fixed factory custody for refused Source installation handoffs.

use super::*;
use crate::qemu_lifecycle_launcher::SourceConstructionCustodyFailure;
use crucible_api::{ProductionVmCleanupHandoff, ProductionVmCleanupStage};

pub(in crate::qemu_campaign_lifecycle) enum RetainedSourceInstall<
    F: QemuAttemptResourceGuardFactory,
> {
    #[cfg(all(target_os = "linux", any(test, feature = "private-measurement-domain")))]
    NativeObservation(Box<dyn super::native_observation::NativeObservationOwner>),
    Unborn(
        crate::qemu_lifecycle_launcher::UnbornSourceConstruction<
            F,
            crate::crucible_qemu_session::QemuAttemptResourceGuardBeginReport,
        >,
    ),
    Api {
        owner: crate::ProductionVmConstructionFailure,
        handoff: Option<Box<dyn ProductionVmCleanupHandoff>>,
    },
    Handoff(Box<dyn ProductionVmCleanupHandoff>),
    ResourceBegin {
        owner: SourceConstructionCustodyFailure<
            crate::crucible_qemu_session::QemuAttemptResourceGuardBeginReport,
        >,
        handoff: Option<Box<dyn ProductionVmCleanupHandoff>>,
    },
    Begin {
        owner: SourceConstructionCustodyFailure,
        handoff: Option<Box<dyn ProductionVmCleanupHandoff>>,
    },
    Storage {
        owner: SourceConstructionCustodyFailure<SourceGenerationStorageRefusal>,
        handoff: Option<Box<dyn ProductionVmCleanupHandoff>>,
    },
    Post {
        owner: SourceConstructionCustodyFailure<SourcePostInstallationRefusal>,
        handoff: Option<Box<dyn ProductionVmCleanupHandoff>>,
    },
    MissingRetirementCarrier {
        lifecycle: ProductionVmLifecycleLoop,
    },
    MissingCallback {
        guard: F::Guard,
        first_cleanup: Option<QemuVmRealizationError>,
    },
}

impl<F> RetainedSourceInstall<F>
where
    F: QemuAttemptResourceGuardFactory + Send + 'static,
    F::Guard: Send + 'static,
{
    /// Returns true only after physical closure without a queue receipt.
    fn retry_publication(&mut self) -> Result<bool, &'static str> {
        let (slot, published) = match self {
            #[cfg(all(target_os = "linux", any(test, feature = "private-measurement-domain")))]
            Self::NativeObservation(_) => {
                return Err("same observation owner requires canonical publication");
            }
            Self::Unborn(owner) => return owner.retry(),
            Self::Api { owner, handoff } => (handoff, owner.retry_reserved_publication()?),
            Self::Begin { owner, handoff } => (handoff, owner.retry_publication()?),
            Self::ResourceBegin { owner, handoff } => (handoff, owner.retry_publication()?),
            Self::Storage { owner, handoff } => (handoff, owner.retry_publication()?),
            Self::Post { owner, handoff } => (handoff, owner.retry_publication()?),
            Self::Handoff(_) => return Err("same Source already retains its cleanup receipt"),
            Self::MissingRetirementCarrier { .. } => {
                return Err("same lifecycle has no reusable construction carrier");
            }
            Self::MissingCallback {
                guard,
                first_cleanup,
            } => {
                if let Err(first) = guard.finish() {
                    if first_cleanup.is_none() {
                        *first_cleanup = Some(first);
                    }
                    return Err("same callback-less Source guard retains cleanup");
                }
                return Ok(true);
            }
        };
        let Some(receipt) = published else {
            // A publication shell cannot substitute for a lost exact-cell receipt.
            return Err("same Source publication has no retained cleanup receipt");
        };
        // Keep the first typed construction cause beside its exact receipt;
        // no returned owner is moved into a diagnostic or discarded here.
        *slot = Some(receipt);
        Ok(false)
    }

    fn handoff_mut(&mut self) -> Option<&mut Box<dyn ProductionVmCleanupHandoff>> {
        match self {
            Self::Handoff(receipt) => Some(receipt),
            Self::Api { handoff, .. }
            | Self::Begin { handoff, .. }
            | Self::ResourceBegin { handoff, .. }
            | Self::Storage { handoff, .. }
            | Self::Post { handoff, .. } => handoff.as_mut(),
            #[cfg(all(target_os = "linux", any(test, feature = "private-measurement-domain")))]
            Self::NativeObservation(_) => None,
            Self::Unborn(_)
            | Self::MissingRetirementCarrier { .. }
            | Self::MissingCallback { .. } => None,
        }
    }

    /// Consumes only a physically completed retainer, moving its actual causes.
    fn into_history(mut self) -> Result<SourceCleanupHistory, Self> {
        if let Some(handoff) = self.handoff_mut()
            && !matches!(handoff.stage(), Ok(ProductionVmCleanupStage::Complete))
        {
            return Err(self);
        }
        let history = match self {
            #[cfg(all(target_os = "linux", any(test, feature = "private-measurement-domain")))]
            Self::NativeObservation(owner) => return Err(Self::NativeObservation(owner)),
            Self::Unborn(owner) => match owner.into_causes() {
                Ok((first, cleanup, cleanup_post)) => SourceCleanupHistory {
                    first: Some(SourceInstallationFirst::ResourceBegin(first)),
                    cleanup,
                    cleanup_post,
                },
                Err(owner) => return Err(Self::Unborn(owner)),
            },
            Self::Handoff(mut handoff) => SourceCleanupHistory {
                first: None,
                cleanup: handoff
                    .take_first_failure()
                    .map(SourceCleanupCause::Scheduler),
                cleanup_post: None,
            },
            Self::Api {
                owner,
                handoff: Some(mut handoff),
            } => match owner.into_published_error() {
                Ok(first) => SourceCleanupHistory {
                    first: Some(SourceInstallationFirst::Api(first)),
                    cleanup: handoff
                        .take_first_failure()
                        .map(SourceCleanupCause::Scheduler),
                    cleanup_post: None,
                },
                Err(owner) => {
                    return Err(Self::Api {
                        owner,
                        handoff: Some(handoff),
                    });
                }
            },
            Self::ResourceBegin {
                owner,
                handoff: Some(mut handoff),
            } => match owner.into_published_error() {
                Ok(first) => SourceCleanupHistory {
                    first: Some(SourceInstallationFirst::ResourceBegin(first)),
                    cleanup: handoff
                        .take_first_failure()
                        .map(SourceCleanupCause::Scheduler),
                    cleanup_post: None,
                },
                Err(owner) => {
                    return Err(Self::ResourceBegin {
                        owner,
                        handoff: Some(handoff),
                    });
                }
            },
            Self::Begin {
                owner,
                handoff: Some(mut handoff),
            } => match owner.into_published_error() {
                Ok(first) => SourceCleanupHistory {
                    first: Some(SourceInstallationFirst::Native(first)),
                    cleanup: handoff
                        .take_first_failure()
                        .map(SourceCleanupCause::Scheduler),
                    cleanup_post: None,
                },
                Err(owner) => {
                    return Err(Self::Begin {
                        owner,
                        handoff: Some(handoff),
                    });
                }
            },
            Self::Storage {
                owner,
                handoff: Some(mut handoff),
            } => match owner.into_published_error() {
                Ok(first) => SourceCleanupHistory {
                    first: Some(SourceInstallationFirst::Storage(first)),
                    cleanup: handoff
                        .take_first_failure()
                        .map(SourceCleanupCause::Scheduler),
                    cleanup_post: None,
                },
                Err(owner) => {
                    return Err(Self::Storage {
                        owner,
                        handoff: Some(handoff),
                    });
                }
            },
            Self::Post {
                owner,
                handoff: Some(mut handoff),
            } => match owner.into_published_error() {
                Ok(first) => SourceCleanupHistory {
                    first: Some(SourceInstallationFirst::Post(first)),
                    cleanup: handoff
                        .take_first_failure()
                        .map(SourceCleanupCause::Scheduler),
                    cleanup_post: None,
                },
                Err(owner) => {
                    return Err(Self::Post {
                        owner,
                        handoff: Some(handoff),
                    });
                }
            },
            Self::MissingCallback {
                guard,
                first_cleanup,
            } => {
                // The caller established actual guard.finish before this cut.
                drop(guard);
                return Ok(first_cleanup.map_or(
                    SourceCleanupHistory {
                        first: None,
                        cleanup: None,
                        cleanup_post: None,
                    },
                    SourceCleanupHistory::from_native,
                ));
            }
            retained => return Err(retained),
        };
        Ok(history)
    }

    pub(super) fn report(&self) -> QemuAttemptProductionVmLifecycleError {
        let diagnostic = match self {
            #[cfg(all(target_os = "linux", any(test, feature = "private-measurement-domain")))]
            Self::NativeObservation(_) => {
                "same Main-worker observation still retains its Source launcher".to_owned()
            }
            Self::Unborn(owner) => match owner.cleanup_failure() {
                Some(cleanup) => format!("{}; cleanup: {cleanup}", owner.first()),
                None => owner.first().to_string(),
            },
            Self::Api { owner, .. } => owner.to_string(),
            Self::Handoff(_) => {
                String::from("same Source cleanup receipt has not reached Complete")
            }
            Self::Begin { owner: first, .. } => first.to_string(),
            Self::ResourceBegin { owner: first, .. } => first.to_string(),
            Self::Storage { owner: first, .. } => first.to_string(),
            Self::Post { owner: first, .. } => first.to_string(),
            Self::MissingRetirementCarrier { .. } => {
                String::from("same returned lifecycle retains missing construction custody")
            }
            Self::MissingCallback {
                first_cleanup: Some(first),
                ..
            } => first.to_string(),
            Self::MissingCallback {
                first_cleanup: None,
                ..
            } => String::from("native begin returned a guard without its before-effects owner"),
        };
        QemuAttemptProductionVmLifecycleError::SourceInstallRetained { diagnostic }
    }
}

impl<R> QemuAttemptProductionVmLifecycleFactory<R>
where
    R: QemuAttemptResourceGuardFactory + Send + 'static,
    R::Guard: QemuAttemptProcessResourceGuard + Send + 'static,
{
    pub(super) fn require_install_vacancy(
        &mut self,
    ) -> Result<(), QemuAttemptProductionVmLifecycleError> {
        if self.lifecycle_outstanding {
            return Err(
                QemuAttemptProductionVmLifecycleError::SourceInstallRetained {
                    diagnostic: String::from("same factory already lent its one live lifecycle"),
                },
            );
        }
        // Drive only the receipt from this factory's preceding attempt. An
        // unrelated global queue scan cannot make this role reusable.
        self.retry_retained_source_installation()
    }

    pub(super) fn retain_cleanup_handoff(&mut self, handoff: Box<dyn ProductionVmCleanupHandoff>) {
        // The exclusive factory borrow spans its checked vacancy and handoff;
        // no callback can install another value in this fixed prepaid slot.
        self.retained_install = Some(RetainedSourceInstall::Handoff(handoff));
    }

    pub(super) fn park_install_from_checked_vacancy(
        &mut self,
        owner: RetainedSourceInstall<R>,
    ) -> QemuAttemptProductionVmLifecycleError {
        // with_attempt_launcher holds the sole &mut factory from the vacancy
        // check through this terminal error cut. Its callback borrows only
        // local pending state; no intervening method writes retained_install.
        self.retained_install = Some(owner);
        self.retained_install.as_ref().map_or(
            QemuAttemptProductionVmLifecycleError::Lifecycle(
                LifecycleApiError::ConstructionCustodyUnavailable,
            ),
            RetainedSourceInstall::report,
        )
    }

    /// Clears physical custody before reporting once-only historical causes.
    fn take_completed_install_history(
        &mut self,
    ) -> Result<(), QemuAttemptProductionVmLifecycleError> {
        let Some(owner) = self.retained_install.take() else {
            return Ok(());
        };
        let history = match owner.into_history() {
            Ok(history) => history,
            Err(owner) => {
                self.retained_install = Some(owner);
                return Err(self.retained_install.as_ref().map_or(
                    QemuAttemptProductionVmLifecycleError::Lifecycle(
                        LifecycleApiError::ConstructionCustodyUnavailable,
                    ),
                    RetainedSourceInstall::report,
                ));
            }
        };
        // Every completed receipt/empty shell was destroyed by into_history.
        // The exact factory is vacant before this historical report escapes.
        if history.is_empty() {
            Ok(())
        } else {
            Err(history.into())
        }
    }

    pub(crate) fn retry_retained_source_installation(
        &mut self,
    ) -> Result<(), QemuAttemptProductionVmLifecycleError> {
        #[cfg(all(target_os = "linux", any(test, feature = "private-measurement-domain")))]
        if matches!(
            self.retained_install,
            Some(RetainedSourceInstall::NativeObservation(_))
        ) {
            return self.retire_native_observation();
        }

        if self.lifecycle_outstanding {
            return Err(
                QemuAttemptProductionVmLifecycleError::SourceInstallRetained {
                    diagnostic: String::from(
                        "same factory still retains an outstanding lifecycle relation",
                    ),
                },
            );
        }
        if let Some(owner) = self.retained_install.as_mut() {
            if owner.handoff_mut().is_none() {
                match owner.retry_publication() {
                    Ok(false) => {}
                    Ok(true) => {
                        // Both no-receipt paths established actual physical
                        // closure before extracting their original typed cause.
                        return self.take_completed_install_history();
                    }
                    Err(_) => return Err(owner.report()),
                }
            }
        }

        let Some(owner) = self.retained_install.as_mut() else {
            return Ok(());
        };
        let Some(receipt) = owner.handoff_mut() else {
            return Err(owner.report());
        };
        // Retry failure is a report, not a stage: a final observation may
        // establish real closure despite an earlier semantic refusal.
        let attempt = receipt.retry();
        let stage = receipt.stage();
        if !matches!(stage, Ok(ProductionVmCleanupStage::Complete)) {
            let diagnostic = match (attempt, stage) {
                (_, Err(first)) | (Err(first), _) => first.to_string(),
                _ => String::from("same Source cleanup body or containing charge remains retained"),
            };
            return Err(
                QemuAttemptProductionVmLifecycleError::SourceInstallRetained { diagnostic },
            );
        }
        self.take_completed_install_history()
    }
}

impl<R> QemuAttemptProductionVmLifecycleFactory<R>
where
    R: QemuAttemptResourceGuardFactory + Send + 'static,
    R::Guard: QemuAttemptProcessResourceGuard + Send + 'static,
{
    pub(crate) fn retain_returned_lifecycle(
        &mut self,
        lifecycle: ProductionVmLifecycleLoop,
    ) -> Result<(), QemuAttemptProductionVmLifecycleError> {
        // Safe factory orchestration admits only one returned lifecycle; every
        // successful build sets this latch and no second build passes vacancy.
        // Installation failure cannot coexist with that successful live value.
        self.lifecycle_outstanding = false;
        match lifecycle.into_construction_custody() {
            Ok(custody) => match custody.publish_for_cleanup() {
                Ok(handoff) => {
                    self.retain_cleanup_handoff(handoff);
                    self.retry_retained_source_installation()
                }
                Err(failure) => Err(self.park_install_from_checked_vacancy(
                    RetainedSourceInstall::Api {
                        owner: failure,
                        handoff: None,
                    },
                )),
            },
            Err(lifecycle) => Err(self.park_install_from_checked_vacancy(
                RetainedSourceInstall::MissingRetirementCarrier { lifecycle },
            )),
        }
    }
}

#[cfg(test)]
mod history_tests {
    use super::*;
    use std::error::Error;

    fn native(message: &str) -> QemuVmRealizationError {
        QemuVmRealizationError::ExecutorUnavailable {
            operation: "component history transport",
            message: message.to_owned(),
        }
    }

    fn message(cause: &SourceCleanupCause) -> &str {
        match cause {
            SourceCleanupCause::Native(QemuVmRealizationError::ExecutorUnavailable {
                message,
                ..
            })
            | SourceCleanupCause::Scheduler(SchedulerError::BoundaryViolation { message })
            | SourceCleanupCause::Body(
                crucible_linux_resource::host_services::process_birth::ServiceBirthError::Policy(
                    message,
                ),
            ) => message,
            _ => panic!("unexpected component error variant"),
        }
    }

    #[test]
    fn history_keeps_constructor_and_each_typed_cleanup_allocation() {
        // Error transport only: no World, closure or cleanup permission is issued.
        let causes = [
            SourceCleanupCause::Scheduler(SchedulerError::BoundaryViolation {
                message: String::from("scheduler cleanup"),
            }),
            SourceCleanupCause::Native(native("native cleanup")),
            SourceCleanupCause::Body(
                crucible_linux_resource::host_services::process_birth::ServiceBirthError::Policy(
                    String::from("body cleanup"),
                ),
            ),
        ];
        for cleanup in causes {
            let cleanup_pointer = message(&cleanup).as_ptr();
            let first = native("constructor first");
            let QemuVmRealizationError::ExecutorUnavailable {
                message: first_message,
                ..
            } = &first
            else {
                panic!("unexpected constructor variant");
            };
            let first_pointer = first_message.as_ptr();
            let history = SourceCleanupHistory {
                first: Some(SourceInstallationFirst::Native(first)),
                cleanup: Some(cleanup),
                cleanup_post: None,
            };

            let original = history
                .source()
                .unwrap()
                .downcast_ref::<QemuVmRealizationError>()
                .unwrap();
            let QemuVmRealizationError::ExecutorUnavailable {
                message: first_message,
                ..
            } = original
            else {
                panic!("constructor source was replaced");
            };
            assert_eq!(first_message.as_ptr(), first_pointer);
            let retained_cleanup = history.cleanup.as_ref().unwrap();
            assert_eq!(message(retained_cleanup).as_ptr(), cleanup_pointer);
            // Trait-object vtables may be duplicated across codegen units.
            assert!(std::ptr::addr_eq(
                history.cleanup_error().unwrap(),
                retained_cleanup.as_error()
            ));
            assert!(!history.is_empty());
        }
    }

    #[test]
    fn cleanup_only_history_exposes_the_underlying_scheduler_error() {
        let history = SourceCleanupHistory {
            first: None,
            cleanup: Some(SourceCleanupCause::Scheduler(
                SchedulerError::BoundaryViolation {
                    message: String::from("actual scheduler cleanup cause"),
                },
            )),
            cleanup_post: None,
        };

        let source = history
            .source()
            .unwrap()
            .downcast_ref::<SchedulerError>()
            .unwrap();
        let cleanup = history
            .cleanup_error()
            .unwrap()
            .downcast_ref::<SchedulerError>()
            .unwrap();

        assert!(std::ptr::eq(source, cleanup));
        assert!(!history.is_empty());
    }

    #[test]
    fn independent_cleanup_post_survives_beside_both_first_causes() {
        use crucible_linux_resource::host_supervision::{HostOperationState, HostSupervisionError};

        // Typed history only; this constructs no World or closure evidence.
        let history = SourceCleanupHistory {
            first: Some(SourceInstallationFirst::Native(native("constructor first"))),
            cleanup: Some(SourceCleanupCause::Native(native("cleanup first"))),
            cleanup_post: Some(HostSupervisionError::Terminal {
                state: HostOperationState::Completed,
            }),
        };

        let original = history
            .source()
            .unwrap()
            .downcast_ref::<QemuVmRealizationError>()
            .unwrap();
        assert!(
            matches!(original, QemuVmRealizationError::ExecutorUnavailable { message, .. }
            if message == "constructor first")
        );
        let cleanup = history
            .cleanup_error()
            .unwrap()
            .downcast_ref::<QemuVmRealizationError>()
            .unwrap();
        assert!(
            matches!(cleanup, QemuVmRealizationError::ExecutorUnavailable { message, .. }
            if message == "cleanup first")
        );
        assert_eq!(
            history.cleanup_post_error(),
            Some(&HostSupervisionError::Terminal {
                state: HostOperationState::Completed,
            })
        );
        assert!(!history.is_empty());

        let post_only = SourceCleanupHistory {
            first: None,
            cleanup: None,
            cleanup_post: history.cleanup_post,
        };
        assert!(
            post_only
                .source()
                .unwrap()
                .downcast_ref::<HostSupervisionError>()
                .is_some()
        );
        assert!(!post_only.is_empty());
    }

    #[test]
    fn source_history_keeps_begin_rollback_separate_from_later_cleanup() {
        // Diagnostic transport only; no Source/World closure is issued here.
        let failure = crate::crucible_qemu_session::QemuAttemptResourceGuardBeginFailure::rollback(
            native("constructor first"),
            crate::crucible_qemu_session::QemuAttemptResourceGuardCleanupFailure::quarantined(
                native("begin rollback"),
            ),
        );
        let (report, _) = failure.into_parts();
        let history = SourceCleanupHistory {
            first: Some(SourceInstallationFirst::ResourceBegin(report)),
            cleanup: Some(SourceCleanupCause::Native(native("later actual cleanup"))),
            cleanup_post: None,
        };

        let report = history
            .resource_begin_error()
            .expect("same typed begin report");
        assert!(
            matches!(report.first_error(), QemuVmRealizationError::ExecutorUnavailable { message, .. } if message == "constructor first")
        );
        assert!(
            matches!(report.cleanup_error(), Some(QemuVmRealizationError::ExecutorUnavailable { message, .. }) if message == "begin rollback")
        );
        let later = history
            .cleanup_error()
            .expect("independent later cleanup")
            .downcast_ref::<QemuVmRealizationError>()
            .expect("same typed native cleanup");
        assert!(
            matches!(later, QemuVmRealizationError::ExecutorUnavailable { message, .. } if message == "later actual cleanup")
        );
    }
}
