//! Fixed factory custody for refused Source installation handoffs.

use super::*;
use crucible_control_api::{ProductionVmCleanupHandoff, ProductionVmCleanupStage};

pub(in crate::qemu_campaign_lifecycle) enum RetainedSourceInstall {
    Api {
        owner: crate::ProductionVmConstructionFailure,
        handoff: Option<SourceCleanupHandoff>,
    },
    Handoff(SourceCleanupHandoff),
    MissingRetirementCarrier {
        lifecycle: ProductionVmLifecycleLoop,
    },
}

impl RetainedSourceInstall {
    /// Publishes this same owner without replacing its exact-cell receipt.
    fn retry_publication(&mut self) -> Result<(), &'static str> {
        let (slot, published) = match self {
            Self::Api { owner, handoff } => (handoff, owner.retry_reserved_publication()?),
            Self::Handoff(_) => return Err("same Source already retains its cleanup receipt"),
            Self::MissingRetirementCarrier { .. } => {
                return Err("same lifecycle has no reusable construction carrier");
            }
        };
        let Some(receipt) = published else {
            // A publication shell cannot substitute for a lost exact-cell receipt.
            return Err("same Source publication has no retained cleanup receipt");
        };
        // Preserve the typed construction cause beside its original receipt.
        *slot = Some(SourceCleanupHandoff::new(receipt));
        Ok(())
    }

    fn handoff_mut(&mut self) -> Option<&mut SourceCleanupReceipt> {
        match self {
            Self::Handoff(receipt) => receipt.receipt_mut(),
            Self::Api { handoff, .. } => {
                handoff.as_mut().and_then(SourceCleanupHandoff::receipt_mut)
            }
            Self::MissingRetirementCarrier { .. } => None,
        }
    }

    /// Consumes only a physically completed retainer, moving its actual causes.
    fn into_history(mut self) -> Result<SourceCleanupHistory, Self> {
        if let Some(handoff) = self.handoff_mut()
            && !matches!(handoff.stage(), Ok(ProductionVmCleanupStage::Complete))
        {
            return Err(self);
        }
        if let Some(handoff) = self.handoff_mut()
            && !handoff.retain_post_body()
        {
            // Body/control completion alone cannot replace actual native,
            // Service and report ownership checks for the full terminal move.
            return Err(self);
        }
        let history = match self {
            Self::Handoff(handoff) => SourceCleanupHistory {
                first: None,
                cleanup: None,
                cleanup_post: None,
                terminal_receipt: Some(handoff),
            },
            Self::Api {
                owner,
                handoff: Some(handoff),
            } => match owner.into_published_error() {
                Ok(first) => SourceCleanupHistory {
                    first: Some(SourceInstallationFirst::Api(first)),
                    cleanup: None,
                    cleanup_post: None,
                    terminal_receipt: Some(handoff),
                },
                Err(owner) => {
                    return Err(Self::Api {
                        owner,
                        handoff: Some(handoff),
                    });
                }
            },
            retained => return Err(retained),
        };
        Ok(history)
    }

    pub(super) fn report(&self) -> QemuAttemptProductionVmLifecycleError {
        let diagnostic = match self {
            Self::Api { owner, .. } => owner.to_string(),
            Self::Handoff(_) => {
                String::from("same Source cleanup receipt has not reached Complete")
            }
            Self::MissingRetirementCarrier { .. } => {
                String::from("same returned lifecycle retains missing construction custody")
            }
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

    pub(super) fn retain_cleanup_handoff(
        &mut self,
        handoff: Box<
            dyn ProductionVmCleanupHandoff<
                    Failure = crate::ProductionVmConstructionCleanupError,
                    PostBody = crate::ProductionVmConstructionPostBody,
                >,
        >,
    ) {
        // The exclusive factory borrow spans its checked vacancy and handoff;
        // no callback can install another value in this fixed prepaid slot.
        self.retained_install = Some(RetainedSourceInstall::Handoff(SourceCleanupHandoff::new(
            handoff,
        )));
    }

    pub(super) fn park_install_from_checked_vacancy(
        &mut self,
        owner: RetainedSourceInstall,
    ) -> QemuAttemptProductionVmLifecycleError {
        // The exclusive factory borrow spans the checked vacancy and this
        // returned-owner handoff; no other method can occupy retained_install.
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
        // The original receipt Box now holds the complete terminal history.
        // Factory custody is vacant; the actual Main role stays pinned until
        // that token allocation and its terminal history are both disposed.
        if history.is_empty() {
            Ok(())
        } else {
            Err(history.into())
        }
    }

    pub(crate) fn retry_retained_source_installation(
        &mut self,
    ) -> Result<(), QemuAttemptProductionVmLifecycleError> {
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
                if owner.retry_publication().is_err() {
                    return Err(owner.report());
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
            | SourceCleanupCause::Cleanup(
                crate::ProductionVmConstructionCleanupError::Scheduler(
                    SchedulerError::BoundaryViolation { message },
                ),
            )
            | SourceCleanupCause::Body(
                crucible_host_resources::host_services::process_birth::ServiceBirthError::Policy(
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
            SourceCleanupCause::Cleanup(crate::ProductionVmConstructionCleanupError::Scheduler(
                SchedulerError::BoundaryViolation {
                    message: String::from("scheduler cleanup"),
                },
            )),
            SourceCleanupCause::Native(native("native cleanup")),
            SourceCleanupCause::Body(
                crucible_host_resources::host_services::process_birth::ServiceBirthError::Policy(
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
                terminal_receipt: None,
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
            history
                .with_cleanup_error(|observed| {
                    use crate::LifecycleFailureRef as Failure;

                    match (retained_cleanup, observed) {
                        (SourceCleanupCause::Cleanup(expected), Failure::BodyCleanup(actual)) => {
                            assert!(std::ptr::eq(expected, actual));
                        }
                        (SourceCleanupCause::Native(expected), Failure::Realization(actual)) => {
                            assert!(std::ptr::eq(expected, actual));
                        }
                        (SourceCleanupCause::Body(expected), Failure::ServiceBirth(actual)) => {
                            assert!(std::ptr::eq(expected, actual));
                        }
                        _ => panic!("the original concrete cleanup cause changed"),
                    }
                })
                .expect("the original cleanup cause remains observable");
            assert!(!history.is_empty());
        }
    }

    #[test]
    fn cleanup_only_history_exposes_the_underlying_scheduler_error() {
        let history = SourceCleanupHistory {
            first: None,
            cleanup: Some(SourceCleanupCause::Cleanup(
                crate::ProductionVmConstructionCleanupError::Scheduler(
                    SchedulerError::BoundaryViolation {
                        message: String::from("actual scheduler cleanup cause"),
                    },
                ),
            )),
            cleanup_post: None,
            terminal_receipt: None,
        };

        let source = history
            .source()
            .unwrap()
            .downcast_ref::<crate::ProductionVmConstructionCleanupError>()
            .unwrap()
            .source()
            .unwrap()
            .downcast_ref::<SchedulerError>()
            .unwrap();
        history
            .with_cleanup_error(|observed| {
                let crate::LifecycleFailureRef::BodyCleanup(cleanup) = observed else {
                    panic!("the actual body cleanup cause remains selected");
                };
                let cleanup = cleanup
                    .source()
                    .unwrap()
                    .downcast_ref::<SchedulerError>()
                    .unwrap();
                assert!(std::ptr::eq(source, cleanup));
            })
            .expect("the original cleanup cause remains observable");
        assert!(!history.is_empty());
    }

    #[test]
    fn independent_cleanup_post_survives_beside_both_first_causes() {
        use crucible_host_resources::host_supervision::{HostOperationState, HostSupervisionError};

        // Typed history only; this constructs no World or closure evidence.
        let history = SourceCleanupHistory {
            first: Some(SourceInstallationFirst::Native(native("constructor first"))),
            cleanup: Some(SourceCleanupCause::Native(native("cleanup first"))),
            cleanup_post: Some(HostSupervisionError::Terminal {
                state: HostOperationState::Completed,
            }),
            terminal_receipt: None,
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
        history
            .with_cleanup_error(|observed| {
                let crate::LifecycleFailureRef::Realization(cleanup) = observed else {
                    panic!("the actual native cleanup cause remains selected");
                };
                assert!(
                    matches!(cleanup, QemuVmRealizationError::ExecutorUnavailable { message, .. }
                if message == "cleanup first")
                );
            })
            .expect("the independent cleanup cause remains observable");
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
            terminal_receipt: None,
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
}
