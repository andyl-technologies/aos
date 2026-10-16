//! Fixed factory custody for refused Source installation handoffs.

use super::*;
use crate::qemu_lifecycle_launcher::SourceConstructionCustodyFailure;
use crucible_api::{ProductionVmCleanupHandoff, ProductionVmCleanupStage};

pub(in crate::qemu_campaign_lifecycle) enum RetainedSourceInstall<G> {
    Api {
        owner: crucible_api::ProductionVmConstructionFailure,
        handoff: Option<Box<dyn ProductionVmCleanupHandoff>>,
    },
    Handoff(Box<dyn ProductionVmCleanupHandoff>),
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
        guard: G,
        first_cleanup: Option<QemuVmRealizationError>,
    },
}

impl<G: QemuAttemptResourceGuard> RetainedSourceInstall<G> {
    /// Returns true only for a callback-less guard that finished without a cell.
    fn retry_publication(&mut self) -> Result<bool, &'static str> {
        let (slot, published) = match self {
            Self::Api { owner, handoff } => (handoff, owner.retry_reserved_publication()?),
            Self::Begin { owner, handoff } => (handoff, owner.retry_publication()?),
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
            | Self::Storage { handoff, .. }
            | Self::Post { handoff, .. } => handoff.as_mut(),
            Self::MissingRetirementCarrier { .. } | Self::MissingCallback { .. } => None,
        }
    }

    pub(super) fn report(&self) -> QemuAttemptProductionVmLifecycleError {
        let diagnostic = match self {
            Self::Api { owner, .. } => owner.to_string(),
            Self::Handoff(_) => {
                String::from("same Source cleanup receipt has not reached Complete")
            }
            Self::Begin { owner: first, .. } => first.to_string(),
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
        owner: RetainedSourceInstall<R::Guard>,
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
                match owner.retry_publication() {
                    Ok(false) => {}
                    Ok(true) => {
                        // Only the callback-less concrete guard has no queue
                        // receipt. Its actual finish succeeded above.
                        self.retained_install = None;
                        return Ok(());
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
        let historical = receipt.first_failure().map(|first| first.to_string());
        let construction = if matches!(owner, RetainedSourceInstall::Handoff(_)) {
            None
        } else {
            // The rejected-publication shell kept its original typed first
            // cause throughout physical progress, alongside the same receipt.
            Some(owner.report())
        };
        // Complete has already transferred the real first cause into this
        // token and acknowledged exact-cell closure. Drop it before new birth.
        self.retained_install = None;
        if let Some(first) = construction {
            return Err(first);
        }
        if let Some(diagnostic) = historical {
            return Err(
                QemuAttemptProductionVmLifecycleError::SourceInstallRetained { diagnostic },
            );
        }
        Ok(())
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
