//! Actual cap-empty Storage startup custody for original-cutoff worker dispatch.
//!
//! The sole admission consumes the real complete inherited capture. Names and
//! PID1 properties are comparisons, not portable authority. It retains the
//! original image, own process and fixed cgroup through every later recheck.
//! Failure closes the owner before returning and keeps partial originals in
//! the typed admission error. No runtime, floor or all-owner drain is proved.

use std::os::fd::OwnedFd;

use aos_sandbox::immutable_image::ImmutableImageErrorV1;
use aos_sandbox::normal_root::{
    NormalRootStartupErrorV1, RejectedStorageWorkerOriginV3, StorageWorkerOriginCauseV3,
    StorageWorkerOriginV3,
};

use super::{CapturedStorageStartupV1, StorageSystemdListenersV1};
use crate::service::StorageServiceError;

/// Preserves the first concrete startup failure; it is not a recovery permit.
#[derive(Debug, thiserror::Error)]
pub(crate) enum StorageOriginalWorkerStartupCauseV3 {
    #[error(transparent)]
    ResourceRecipient(aos_sandbox::normal_root::StorageResourceRecipientErrorV1),
    #[error(transparent)]
    Service(#[from] StorageServiceError),
    #[error(transparent)]
    Linux(#[from] aos_sandbox_linux::Error),
    #[error(transparent)]
    Image(#[from] ImmutableImageErrorV1),
    #[error(transparent)]
    Observation(#[from] NormalRootStartupErrorV1),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("original Storage worker startup is unavailable or differs")]
    Binding,
    #[error("original Storage worker startup is permanently closed")]
    Closed,
}

/// Owns rejected original startup custody and its first typed cause.
///
/// This cannot be converted into admitted startup or retried with new facts.
pub struct StorageOriginalWorkerStartupErrorV3 {
    cause: StorageOriginalWorkerStartupCauseV3,
    rejected: Option<RejectedStorageWorkerOriginV3>,
    admitted: Option<StorageOriginalWorkerStartupV3>,
}

impl std::fmt::Debug for StorageOriginalWorkerStartupErrorV3 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (retained_capture, retained_partial) = self
            .rejected
            .as_ref()
            .map_or(
                (false, false),
                RejectedStorageWorkerOriginV3::retained_prefix_presence,
            );
        formatter
            .debug_struct("StorageOriginalWorkerStartupErrorV3")
            .field("cause", &self.cause)
            .field("retained_capture", &retained_capture)
            .field("retained_partial", &retained_partial)
            .field("retained_startup", &self.admitted.is_some())
            .finish()
    }
}

impl std::fmt::Display for StorageOriginalWorkerStartupErrorV3 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.cause.fmt(formatter)
    }
}

impl std::error::Error for StorageOriginalWorkerStartupErrorV3 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.cause)
    }
}

impl From<StorageServiceError> for StorageOriginalWorkerStartupErrorV3 {
    fn from(error: StorageServiceError) -> Self {
        Self {
            cause: error.into(),
            rejected: None,
            admitted: None,
        }
    }
}

impl StorageOriginalWorkerStartupErrorV3 {
    /// Keeps real startup custody after a later legacy Security admission error.
    ///
    /// This is failure ownership only; it constructs no admitted owner or grant.
    #[must_use]
    pub fn retain_service_failure(
        error: StorageServiceError,
        mut startup: Option<StorageOriginalWorkerStartupV3>,
    ) -> Self {
        if let Some(startup) = startup.as_mut() {
            startup.original.close();
        }
        Self {
            cause: error.into(),
            rejected: None,
            admitted: startup,
        }
    }

    pub(crate) fn retain_closed(
        cause: StorageOriginalWorkerStartupCauseV3,
        mut startup: StorageOriginalWorkerStartupV3,
    ) -> Self {
        startup.original.close();
        Self {
            cause,
            rejected: None,
            admitted: Some(startup),
        }
    }
}

/// Retains genuine fixed Storage startup without floor or effect authority.
///
/// It has no caller FD, PID, path, scalar, profile, or observation constructor.
/// It is move-only; only its same original runtime may borrow it for rechecks.
pub struct StorageOriginalWorkerStartupV3 {
    original: StorageWorkerOriginV3,
}

impl StorageOriginalWorkerStartupV3 {
    /// Pre-arms before any observation; Err, unwind, drop and forget stay closed.
    pub(crate) fn recheck(&mut self) -> Result<(), StorageOriginalWorkerStartupCauseV3> {
        self.original.recheck().map_err(project_origin_cause)
    }
}

pub(super) fn admit_captured(
    captured: CapturedStorageStartupV1,
) -> Result<
    (
        StorageSystemdListenersV1,
        Option<OwnedFd>,
        Option<StorageOriginalWorkerStartupV3>,
    ),
    StorageOriginalWorkerStartupErrorV3,
> {
    match captured.original.into_original_worker_parts() {
        Ok((listeners, image, startup)) => Ok((
            listeners,
            image,
            startup.map(|original| StorageOriginalWorkerStartupV3 { original }),
        )),
        Err(error) => {
            let (cause, rejected) = error.into_failure();
            Err(StorageOriginalWorkerStartupErrorV3 {
                cause: project_origin_cause(cause),
                rejected: Some(rejected),
                admitted: None,
            })
        }
    }
}

pub(super) fn admit_resource_recipient(
    captured: aos_sandbox::normal_root::StorageResourceRecipientCaptureV1,
) -> Result<
    (StorageSystemdListenersV1, Option<OwnedFd>, Option<StorageOriginalWorkerStartupV3>),
    StorageOriginalWorkerStartupErrorV3,
> {
    match captured.into_worker_parts() {
        Ok((listeners, image, startup)) => Ok((
            listeners, image,
            startup.map(|original| StorageOriginalWorkerStartupV3 { original }),
        )),
        Err(error) => Err(StorageOriginalWorkerStartupErrorV3 {
            cause: StorageOriginalWorkerStartupCauseV3::ResourceRecipient(error),
            rejected: None,
            admitted: None,
        }),
    }
}

// The fixed opener had only Kernel and Linux failures. Restore its original
// Storage service nesting; all other actual causes keep their former variant.
fn project_origin_cause(cause: StorageWorkerOriginCauseV3) -> StorageOriginalWorkerStartupCauseV3 {
    match cause {
        StorageWorkerOriginCauseV3::Linux(error) => StorageOriginalWorkerStartupCauseV3::Linux(error),
        StorageWorkerOriginCauseV3::CgroupKernel(error) => {
            StorageOriginalWorkerStartupCauseV3::Service(StorageServiceError::Runtime(
                crate::StorageRuntimeError::Worker(crate::ZfsWorkerError::Kernel(error)),
            ))
        }
        StorageWorkerOriginCauseV3::Image(error) => StorageOriginalWorkerStartupCauseV3::Image(error),
        StorageWorkerOriginCauseV3::Observation(error) => {
            StorageOriginalWorkerStartupCauseV3::Observation(error)
        }
        StorageWorkerOriginCauseV3::Io(error) => StorageOriginalWorkerStartupCauseV3::Io(error),
        StorageWorkerOriginCauseV3::Binding => StorageOriginalWorkerStartupCauseV3::Binding,
        StorageWorkerOriginCauseV3::Closed => StorageOriginalWorkerStartupCauseV3::Closed,
    }
}
