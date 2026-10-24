//! Closes the original launch controller before dropping its retained custody.
//!
//! Typed and erased observers share the same private control. Neither raw Arc
//! aliases nor weak controller headers escape this owner.

use super::{OriginalActorAccountError, OriginalNativeFreshLaunchError};
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
