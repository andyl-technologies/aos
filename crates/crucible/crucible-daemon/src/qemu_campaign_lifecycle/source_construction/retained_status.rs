//! Preserves actual Source cleanup and independent stage-observation refusals.
//!
//! These inline reports move returned typed errors without formatting them or
//! allocating replacement diagnostics. The factory retains the actual body and
//! first constructor cause until its existing terminal handoff completes.

use std::error::Error;
use std::fmt;

use crucible_control_api::LifecycleApiError;

/// Retains both returned refusals while the original Source remains owned.
#[derive(Debug)]
pub struct SourceInstallationCleanupRefusal {
    cleanup: Option<LifecycleApiError>,
    observation: Option<LifecycleApiError>,
}

impl SourceInstallationCleanupRefusal {
    pub(super) fn new(
        cleanup: Option<LifecycleApiError>,
        observation: Option<LifecycleApiError>,
    ) -> Option<Self> {
        if cleanup.is_none() && observation.is_none() {
            return None;
        }
        Some(Self {
            cleanup,
            observation,
        })
    }

    /// Borrows the refusal returned by the actual cleanup invocation.
    #[must_use]
    pub fn cleanup_error(&self) -> Option<&LifecycleApiError> {
        self.cleanup.as_ref()
    }

    /// Borrows the independent refusal returned by the stage observation.
    #[must_use]
    pub fn observation_error(&self) -> Option<&LifecycleApiError> {
        self.observation.as_ref()
    }
}

impl fmt::Display for SourceInstallationCleanupRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (&self.cleanup, &self.observation) {
            (Some(cleanup), Some(observation)) => {
                write!(
                    formatter,
                    "{cleanup}; independent stage observation: {observation}"
                )
            }
            (Some(first), None) | (None, Some(first)) => fmt::Display::fmt(first, formatter),
            (None, None) => unreachable!("a retained cleanup refusal contains an actual error"),
        }
    }
}

impl Error for SourceInstallationCleanupRefusal {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.cleanup
            .as_ref()
            .or(self.observation.as_ref())
            .map(|first| first as &dyn Error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::qemu_campaign_lifecycle::source_construction::retained::{
        RetainedSourceInstall, retained_cleanup_report,
    };
    use crate::{ProductionVmConstructionCustody, QemuAttemptProductionVmLifecycleError};
    use crucible_control_api::ProductionVmCleanupStage;
    use crucible_host_resources::test_support::TestAllocationObserver;

    fn pointer(error: &LifecycleApiError) -> *const u8 {
        let LifecycleApiError::LoopFactory { message } = error else {
            panic!("actual component cause remains a typed factory refusal");
        };
        message.as_ptr()
    }

    fn refusal(message: &str) -> LifecycleApiError {
        LifecycleApiError::LoopFactory {
            message: String::from(message),
        }
    }

    #[test]
    fn both_actual_cleanup_refusals_move_without_rendering_or_allocation() {
        // Transport only: these errors establish no native Source or return.
        let cleanup = refusal("actual cleanup refusal");
        let observation = refusal("independent stage observation refusal");
        let cleanup_pointer = pointer(&cleanup);
        let observation_pointer = pointer(&observation);

        let (error, counts) = TestAllocationObserver::count(|| {
            retained_cleanup_report(Err(cleanup), Err(observation))
        });

        assert_eq!(counts.allocations, 0);
        assert_eq!(counts.reallocations, 0);
        assert!(!counts.overflow);
        let QemuAttemptProductionVmLifecycleError::SourceInstallRetained {
            source: Some(source),
            ..
        } = &error
        else {
            panic!("both actual refusals remain typed");
        };
        assert_eq!(pointer(source.cleanup_error().unwrap()), cleanup_pointer);
        assert_eq!(
            pointer(source.observation_error().unwrap()),
            observation_pointer
        );
        let first = error
            .source()
            .unwrap()
            .downcast_ref::<SourceInstallationCleanupRefusal>()
            .unwrap();
        assert!(std::ptr::eq(first, source));
        assert!(std::ptr::eq(
            first
                .source()
                .unwrap()
                .downcast_ref::<LifecycleApiError>()
                .unwrap(),
            source.cleanup_error().unwrap(),
        ));
    }

    #[test]
    fn independent_observation_is_the_source_when_cleanup_has_no_refusal() {
        let observation = refusal("actual stage refusal");
        let original = pointer(&observation);

        let (error, counts) = TestAllocationObserver::count(|| {
            retained_cleanup_report(Ok(ProductionVmCleanupStage::Complete), Err(observation))
        });

        assert_eq!(counts.allocations, 0);
        assert_eq!(counts.reallocations, 0);
        assert!(!counts.overflow);
        let first = error
            .source()
            .unwrap()
            .source()
            .unwrap()
            .downcast_ref::<LifecycleApiError>()
            .unwrap();
        assert_eq!(pointer(first), original);
        assert!(SourceInstallationCleanupRefusal::new(None, None).is_none());
    }

    #[test]
    fn repeated_factory_reports_keep_the_original_typed_constructor_without_rendering() {
        // The empty component carrier owns no physical launch or Main role.
        let first = refusal("original construction refusal");
        let original = pointer(&first);
        let owner = Box::new(ProductionVmConstructionCustody::new()).into_failure(first);
        let retained = RetainedSourceInstall::Api {
            owner,
            handoff: None,
        };

        let ((first_report, repeated), counts) =
            TestAllocationObserver::count(|| (retained.report(), retained.report()));

        assert_eq!(counts.allocations, 0);
        assert_eq!(counts.reallocations, 0);
        assert!(!counts.overflow);
        for report in [first_report, repeated] {
            assert!(matches!(
                report,
                QemuAttemptProductionVmLifecycleError::SourceInstallRetained { source: None, .. }
            ));
        }
        let RetainedSourceInstall::Api { owner, .. } = &retained else {
            panic!("the exact original construction carrier remains owned");
        };
        assert_eq!(pointer(owner.first_error().unwrap()), original);
    }
}
