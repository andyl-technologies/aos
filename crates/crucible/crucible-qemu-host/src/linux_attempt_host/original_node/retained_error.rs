//! Closes the original launch controller before dropping its retained custody.
//!
//! Typed and erased observers share the same private control. Neither raw Arc
//! aliases nor weak controller headers escape this owner.

use super::{FreshLaunchCause, OriginalActorAccountError, OriginalNativeFreshLaunchError};
use crucible_engine::{BackendOperationalCause, SharedOperationalCause};
use crucible_host_resources::host_services::process_birth::{
    AuthenticatedSourceHostPurpose, SourceHostControlLease,
};
use crucible_host_resources::host_supervision::HostOperationGuard;
use std::error::Error;
use std::fmt;
use std::ops::Deref;

/// Keeps the actual Main payer and controller loan in their funded body.
pub(in crate::linux_attempt_host) struct LaunchControllerFunding {
    pub(in crate::linux_attempt_host) host: AuthenticatedSourceHostPurpose,
    _control: SourceHostControlLease,
    pub(super) helper_first: Option<crate::spawn::helper_first::HelperFirstJournal>,
}

impl LaunchControllerFunding {
    /// Reserves the controller's actual Main loan before its shared allocation.
    ///
    /// # Errors
    /// Refuses exhausted Main capacity or a different, expired Original.
    pub(in crate::linux_attempt_host) fn reserve(
        host: AuthenticatedSourceHostPurpose,
        original: &HostOperationGuard,
    ) -> Result<Self, OriginalActorAccountError> {
        let bytes = controller_peak_bytes()?;
        let control = host.reserve_controls(0, bytes)?;
        control.verify_original_capacity(original, 0, bytes)?;

        let first_bytes = crate::spawn::helper_first::control_peak_bytes()
            .ok_or(OriginalActorAccountError::Unavailable)?;
        let helper_first = host.reserve_controls(0, first_bytes)?;
        helper_first.verify_original_capacity(original, 0, first_bytes)?;

        Ok(Self {
            host,
            _control: control,
            helper_first: Some(crate::spawn::helper_first::HelperFirstJournal::new(
                helper_first,
            )),
        })
    }
}

/// Covers the live shared controller and its final extracted destruction frame.
///
/// # Errors
/// Refuses an unrepresentable shared layout or combined destruction extent.
pub(in crate::linux_attempt_host) fn controller_peak_bytes()
-> Result<u64, OriginalActorAccountError> {
    SharedOperationalCause::<OriginalNativeFreshLaunchError>::allocation_bytes()
        .ok()
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<OriginalNativeFreshLaunchError>()))
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or(OriginalActorAccountError::Unavailable)
}

/// Retains one original fresh-launch failure and its physical cleanup custody.
///
/// Every typed and erased observer consumes the same closed shared owner. Its
/// final observer frees the controller allocation before dropping its concrete
/// error and retained resource loans. This ordering grants no physical-return
/// receipt and does not fund separately allocated diagnostic payloads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetainedNativeFreshLaunchError {
    source: SharedOperationalCause<OriginalNativeFreshLaunchError>,
}

impl RetainedNativeFreshLaunchError {
    pub(super) fn new(source: OriginalNativeFreshLaunchError) -> Self {
        Self {
            source: SharedOperationalCause::new(source),
        }
    }

    /// Saves the initiating refusal in its prebirth controller before a postcut.
    ///
    /// Sharing this same owner neither allocates another diagnostic body nor
    /// transfers any retained child or cleanup authority.
    pub(super) fn retain_primary(&self, primary: FreshLaunchCause) -> Self {
        self.record(primary, None);
        self.clone()
    }

    /// Shares the same concrete original through the portable backend boundary.
    ///
    /// This observer allocates no new body and retains the original error's
    /// downcast identity. It grants no operation, cleanup or return authority.
    #[must_use]
    pub fn backend_cause(&self) -> BackendOperationalCause {
        self.source.backend_cause()
    }

    /// Compares existing controller allocations without authorizing their use.
    #[must_use]
    pub fn same_owner(&self, other: &Self) -> bool {
        self.source == other.source
    }
}

impl Deref for RetainedNativeFreshLaunchError {
    type Target = OriginalNativeFreshLaunchError;

    fn deref(&self) -> &Self::Target {
        self.source.source_ref()
    }
}

impl AsRef<OriginalNativeFreshLaunchError> for RetainedNativeFreshLaunchError {
    fn as_ref(&self) -> &OriginalNativeFreshLaunchError {
        self.source.source_ref()
    }
}

impl fmt::Display for RetainedNativeFreshLaunchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.source.source_ref().fmt(formatter)
    }
}

impl Error for RetainedNativeFreshLaunchError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.source.source_ref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        QemuLiveNodeStepGateError, QemuNodeChannelPlane, QemuNodeError, QemuNodeStepOperation,
    };
    use crucible_host_resources::host_supervision::{
        HostOperationBudgets, HostOperationClass, HostOperationSupervisor,
    };
    use crucible_host_resources::test_support::TestAllocationObserver;
    use std::borrow::Cow;
    use std::sync::Arc;

    #[test]
    fn primary_is_retained_before_independent_post_without_another_allocation() {
        const OPERATION: QemuNodeStepOperation = QemuNodeStepOperation::new("component launch");
        let supervisor =
            HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
        let original = Arc::new(supervisor.begin(HostOperationClass::Preparation).unwrap());
        let controller = OriginalNativeFreshLaunchError::prepare_unissued(&original);
        let message = String::from("existing launch payload");
        let payload = message.as_ptr();
        let primary = FreshLaunchCause::Launch(QemuLiveNodeStepGateError::Step {
            operation: &OPERATION,
            source: QemuNodeError::Channel {
                plane: QemuNodeChannelPlane::QmpMachineControl,
                operation: "component channel",
                message: Cow::Owned(message),
            },
        });

        let (retained, counts) =
            TestAllocationObserver::count(|| controller.retain_primary(primary));

        assert_eq!(counts.allocations, 0);
        assert_eq!(counts.reallocations, 0);
        assert!(!counts.overflow);
        assert!(retained.same_owner(&controller));
        assert!(retained.original_after().is_none());
        let first = controller.primary.get().unwrap();
        let FreshLaunchCause::Launch(QemuLiveNodeStepGateError::Step {
            source: QemuNodeError::Channel { message, .. },
            ..
        }) = first
        else {
            panic!("the original typed launch cause must already be retained");
        };
        assert_eq!(message.as_ptr(), payload);
        assert!(std::ptr::eq(
            controller
                .as_ref()
                .source()
                .unwrap()
                .downcast_ref::<FreshLaunchCause>()
                .unwrap(),
            first,
        ));

        supervisor.cancel().unwrap();
        let after = original.wait_slice().unwrap_err();
        let ((), counts) = TestAllocationObserver::count(|| {
            retained.record_original_after(Some(after));
        });

        assert_eq!(counts.allocations, 0);
        assert_eq!(counts.reallocations, 0);
        assert!(!counts.overflow);
        assert_eq!(controller.original_after(), Some(&after));
        assert!(std::ptr::eq(controller.primary.get().unwrap(), first));

        // A later adapter cannot replace either saved observation.
        let later = controller.retain_primary(FreshLaunchCause::Binding(
            OriginalActorAccountError::Unavailable,
        ));
        assert!(later.same_owner(&retained));
        assert!(std::ptr::eq(controller.primary.get().unwrap(), first));
        assert_eq!(later.original_after(), Some(&after));
    }
}
