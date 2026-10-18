//! Retains a refused child installation and its enclosing source authorities.
//!
//! This value occupies a fixed slot in the Main-owned factory. Its API carrier
//! is the same preallocated World body; publication and retirement never create
//! a replacement owner or an operational allowance.

use super::*;
use crate::{ProductionVmConstructionCleanupError, ProductionVmConstructionFailure};
use crucible_api::{ProductionVmCleanupHandoff, ProductionVmCleanupStage};
use crucible_linux_resource::host_supervision::{HostOperationGuard, HostSupervisionError};

use crate::qemu_hot_fork_world_resource::{
    QemuHotForkWorldReleaseReadiness, QemuHotForkWorldReleaseReadinessError,
};

/// Distinguishes an already quarantined refusal from still-owned construction.
pub(crate) enum HotForkLifecycleInstallError<G: QemuAttemptProcessResourceGuard> {
    /// Earlier assembly cleanup retained its existing quarantine owners.
    Lifecycle(LifecycleApiError),
    /// The complete construction and its enclosing owners still require return.
    Retained(RetainedHotForkInstallation<G>),
}

impl<G: QemuAttemptProcessResourceGuard> From<LifecycleApiError>
    for HotForkLifecycleInstallError<G>
{
    fn from(error: LifecycleApiError) -> Self {
        Self::Lifecycle(error)
    }
}

/// Reports physical retirement without carrying or copying its owning body.
#[derive(Debug, thiserror::Error)]
pub(crate) enum HotForkInstallationRetirementError {
    /// The existing operation no longer permits another cleanup step.
    #[error("retained installation's original retirement operation refused")]
    Operation(#[source] HostSupervisionError),
    /// The exact API carrier still owns unfinished physical cleanup.
    #[error("retained installation construction cleanup refused")]
    Construction(#[source] ProductionVmConstructionCleanupError),
    /// Its original Main cell has not accepted the owning carrier.
    #[error("retained installation publication remains refused")]
    Publication,
    /// The exact cleanup receipt refused observation or physical progress.
    #[error("retained installation cleanup receipt refused")]
    Cleanup(#[source] LifecycleApiError),
    /// Native handoff or source/target disposition remains uncertain.
    #[error("retained installation reconciliation refused")]
    Reconciliation(#[source] LifecycleApiError),
    /// Aggregate readiness could not be observed without borrowing its owner.
    #[error("retained installation aggregate readiness refused")]
    Readiness(#[source] QemuHotForkWorldReleaseReadinessError),
    /// The actual aggregate guard refused physical release.
    #[error("retained installation aggregate release refused")]
    Aggregate(#[source] crate::QemuAttemptResourceGuardCleanupFailure),
    /// Physical return completed while earlier real cleanup reports remain.
    #[error("retained installation physically returned after earlier failures: {0}")]
    Historical(#[source] HotForkInstallationHistory),
    /// Another original-owner step must run before the next bounded retry.
    #[error("retained installation still awaits physical retirement")]
    Pending,
    /// A source alias or poisoned mutex prevents exact restoration.
    #[error("retained installation source remains borrowed or poisoned")]
    SourceUnavailable,
    /// The existing source supervisor could not be restored.
    #[error("retained installation source supervision restoration refused")]
    SourceRestoration(#[source] SchedulerError),
    /// The fixed slot no longer contains its exact checked-out source lease.
    #[error("retained installation source lease is absent")]
    MissingSource,
}

/// Moves existing historical causes alongside a physically returned Source.
#[derive(Debug, Default)]
pub(crate) struct HotForkInstallationHistory {
    construction: Option<LifecycleApiError>,
    // Keeps the actual completed Main role and every typed leaf together.
    // This is not a detached cleanup report or another owning allocation.
    post_body: Option<crate::ProductionVmConstructionPostBody>,
}

impl HotForkInstallationHistory {
    pub(crate) fn is_empty(&self) -> bool {
        self.construction.is_none()
            && self
                .post_body
                .as_ref()
                .is_none_or(|body| body.first_failure().is_none())
    }
}

impl std::fmt::Display for HotForkInstallationHistory {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "construction: {:?}; completed Main role: {:?}",
            self.construction, self.post_body
        )
    }
}

impl std::error::Error for HotForkInstallationHistory {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Some(first) = &self.construction {
            return Some(first);
        }
        self.post_body
            .as_ref()
            .and_then(|body| body.first_failure())
    }
}

/// Keeps the exact API failure, source lease and aggregate resources together.
pub(crate) struct RetainedHotForkInstallation<G: QemuAttemptProcessResourceGuard> {
    construction: Option<ProductionVmConstructionFailure>,
    cleanup_handoff: Option<
        Box<
            dyn ProductionVmCleanupHandoff<
                    Failure = crate::ProductionVmConstructionCleanupError,
                    PostBody = crate::ProductionVmConstructionPostBody,
                >,
        >,
    >,
    source_lease: Option<QemuHotForkSourceWorldLease>,
    source_world: Arc<Mutex<ProductionVmHotForkSourceWorld>>,
    reconciliations: LinuxQemuHotForkWorldReconciliationSet<G>,
    resources: QemuHotForkWorldResourceOwner<G>,
    auxiliary_resources: Option<QemuHotForkWorldAuxiliaryResourceBroker<G>>,
    handoff_confirmed: bool,
    reconciled: bool,
    aggregate_released: bool,
    history: HotForkInstallationHistory,
}

impl<G: QemuAttemptProcessResourceGuard> RetainedHotForkInstallation<G> {
    pub(super) fn new(
        construction: ProductionVmConstructionFailure,
        source_lease: QemuHotForkSourceWorldLease,
        source_world: Arc<Mutex<ProductionVmHotForkSourceWorld>>,
        reconciliations: LinuxQemuHotForkWorldReconciliationSet<G>,
        resources: QemuHotForkWorldResourceOwner<G>,
        auxiliary_resources: Option<QemuHotForkWorldAuxiliaryResourceBroker<G>>,
    ) -> Self {
        Self {
            construction: Some(construction),
            cleanup_handoff: None,
            source_lease: Some(source_lease),
            source_world,
            reconciliations,
            resources,
            auxiliary_resources,
            handoff_confirmed: false,
            reconciled: false,
            aggregate_released: false,
            history: HotForkInstallationHistory::default(),
        }
    }

    /// Reports fixture history while retaining its actual construction body here.
    ///
    /// This is not Main publication, physical cleanup or Source restoration.
    #[cfg(test)]
    pub(crate) fn take_component_construction_cause(&mut self) -> Option<LifecycleApiError> {
        self.construction.as_mut()?.take_component_first_error()
    }

    /// Publishes the same carrier without dropping it on a refused handoff.
    ///
    /// # Errors
    /// Leaves the exact returned carrier or token and owner in this slot.
    pub(crate) fn publish_construction(
        &mut self,
    ) -> Result<Option<LifecycleApiError>, HotForkInstallationRetirementError> {
        if self.cleanup_handoff.is_some() {
            return Ok(None);
        }
        let Some(failure) = self.construction.take() else {
            return Err(HotForkInstallationRetirementError::Publication);
        };
        match failure.retain_in_reserved_cleanup() {
            Ok((first, handoff)) => {
                self.cleanup_handoff = Some(handoff);
                Ok(Some(first))
            }
            Err(mut failure) => {
                let published = failure.retry_reserved_publication();
                // A rejected handoff keeps its original typed cause beside
                // the exact receipt until physical retirement is complete.
                self.construction = Some(failure);
                match published {
                    Ok(Some(handoff)) => {
                        self.cleanup_handoff = Some(handoff);
                        Ok(None)
                    }
                    Ok(None) | Err(_) => Err(HotForkInstallationRetirementError::Publication),
                }
            }
        }
    }

    fn advance_cleanup(
        &mut self,
    ) -> Result<ProductionVmCleanupStage, HotForkInstallationRetirementError> {
        let handoff = self
            .cleanup_handoff
            .as_mut()
            .ok_or(HotForkInstallationRetirementError::Publication)?;
        // A retry may report an earlier refusal after destroying the body.
        // Observe the physical stage separately so that aggregate retirement
        // can return a charge which the same receipt is waiting to close.
        let attempt = handoff.retry();
        let stage = handoff
            .stage()
            .map_err(HotForkInstallationRetirementError::Cleanup)?;
        if stage == ProductionVmCleanupStage::BodyRetained {
            attempt.map_err(HotForkInstallationRetirementError::Cleanup)?;
        }
        Ok(stage)
    }

    /// Advances actual cleanup using the supplied existing retirement operation.
    ///
    /// # Errors
    /// Retains all fields on an expired operation, physical cleanup refusal,
    /// unpublished carrier, unfinished reconciliation or aggregate refusal.
    pub(crate) fn advance_original_retirement(
        &mut self,
        original: &HostOperationGuard,
    ) -> Result<
        Option<(QemuHotForkSourceWorldLease, HotForkInstallationHistory)>,
        HotForkInstallationRetirementError,
    > {
        use HotForkInstallationRetirementError as Error;

        check_original(original)?;
        if self.history.post_body.is_some() {
            // The role has already moved intact. Retry only final Source
            // restoration; there is no receipt left to publish, drive or reap.
            return self.restore_terminal_source(original);
        }
        if self.cleanup_handoff.is_none()
            && let Some(construction) = self.construction.as_ref()
        {
            construction.retry_cleanup().map_err(Error::Construction)?;
        }
        self.publish_construction()?;
        if self.advance_cleanup()? == ProductionVmCleanupStage::BodyRetained {
            return Ok(None);
        }
        check_original(original)?;

        // Handoff is observed once, before disposition advances the native
        // reconciliation state. Later retries must resume that current state.
        if !self.handoff_confirmed {
            self.reconciliations
                .validate_operational_handoff()
                .map_err(Error::Reconciliation)?;
            self.handoff_confirmed = true;
        }
        if !self.reconciled {
            let step = self
                .reconciliations
                .reconcile_execution_disposition(AttemptExecutionDisposition::Failed)
                .map_err(Error::Reconciliation)?;
            self.reconciled = step == AttemptExecutionReconciliationStep::Complete;
            check_original(original)?;
            if !self.reconciled {
                return Ok(None);
            }
        }
        if !self.aggregate_released {
            // Main may own the published API carrier but not yet have retried
            // its launcher. Observing readiness must never quarantine it.
            if self
                .resources
                .release_readiness()
                .map_err(Error::Readiness)?
                != QemuHotForkWorldReleaseReadiness::Ready
            {
                return Ok(None);
            }
            self.resources.finish().map_err(Error::Aggregate)?;
            self.aggregate_released = true;
            self.auxiliary_resources = None;
        }
        if self.advance_cleanup()? != ProductionVmCleanupStage::Complete {
            return Ok(None);
        }
        if self.history.post_body.is_none() {
            let handoff = self.cleanup_handoff.take().ok_or(Error::Publication)?;
            match handoff.into_post_body() {
                Ok(body) => self.history.post_body = Some(body),
                Err(handoff) => {
                    // The same receipt still owns the actual role. Neither a
                    // Complete observation nor an error grants role reuse.
                    self.cleanup_handoff = Some(handoff);
                    return Ok(None);
                }
            }
        }
        self.restore_terminal_source(original)
    }

    /// Retries the terminal metadata handback without reusing a moved receipt.
    fn restore_terminal_source(
        &mut self,
        original: &HostOperationGuard,
    ) -> Result<
        Option<(QemuHotForkSourceWorldLease, HotForkInstallationHistory)>,
        HotForkInstallationRetirementError,
    > {
        use HotForkInstallationRetirementError as Error;

        if let Some(shell) = self.construction.take() {
            match shell.into_published_error() {
                Ok(first) => self.history.construction = Some(first),
                Err(shell) => {
                    self.construction = Some(shell);
                    return Err(Error::Publication);
                }
            }
        }
        // The exact receipt has acknowledged destruction and charge return.
        // Keep the completed receipt and its error shell through restoration;
        // the factory drops this containing value before reusing the Source.
        check_original(original)?;
        self.source_world
            .try_lock()
            .map_err(|_| Error::SourceUnavailable)?
            .restore_retained_service_supervisor()
            .map_err(Error::SourceRestoration)?;
        let source = self.source_lease.take().ok_or(Error::MissingSource)?;
        // Returning history cannot prevent restoring this physically retired
        // Source. Move its actual causes only after restoration succeeds.
        Ok(Some((source, std::mem::take(&mut self.history))))
    }
}

fn check_original(original: &HostOperationGuard) -> Result<(), HotForkInstallationRetirementError> {
    original
        .wait_slice()
        .map(|_| ())
        .map_err(HotForkInstallationRetirementError::Operation)
}

#[cfg(test)]
mod completed_history_tests {
    use super::*;

    #[test]
    fn completed_target_history_keeps_the_actual_typed_cleanup_allocation() {
        // Local report storage only: no Main, Source, receipt or return is
        // issued by this history-only value.
        let message = String::from("actual component cleanup allocation");
        let allocation = message.as_ptr();
        let first = crate::ProductionVmConstructionCleanupError::Authority(
            LifecycleApiError::LoopFactory { message },
        );
        let mut body = crate::ProductionVmConstructionPostBody::history_only();
        body.retain_cleanup_first(first);
        let history = HotForkInstallationHistory {
            construction: None,
            post_body: Some(body),
        };

        assert!(!history.is_empty());
        let first = std::error::Error::source(&history)
            .unwrap()
            .downcast_ref::<crate::ProductionVmConstructionCleanupError>()
            .unwrap();
        let crate::ProductionVmConstructionCleanupError::Authority(
            LifecycleApiError::LoopFactory { message },
        ) = first
        else {
            panic!("the actual typed cleanup report changed");
        };
        assert_eq!(message.as_ptr(), allocation);
    }

    #[test]
    fn construction_precedence_and_empty_history_observation_remain_separate() {
        let mut body = crate::ProductionVmConstructionPostBody::history_only();
        body.retain_cleanup_first(crate::ProductionVmConstructionCleanupError::Retained(
            "independent component cleanup report",
        ));
        let history = HotForkInstallationHistory {
            construction: Some(LifecycleApiError::CleanupRetained),
            post_body: Some(body),
        };

        assert!(!history.is_empty());
        assert!(
            std::error::Error::source(&history)
                .unwrap()
                .downcast_ref::<LifecycleApiError>()
                .is_some()
        );
        let empty = HotForkInstallationHistory {
            construction: None,
            post_body: Some(crate::ProductionVmConstructionPostBody::history_only()),
        };
        assert!(empty.is_empty());
        assert!(empty.post_body.is_some());
    }
}
