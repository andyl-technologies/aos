//! Retains an expired capture's original failure under its admitted metadata loan.
//!
//! Expiration remains the outer operational classification. The cause records
//! the actual launch or capture error without renewing its deadline or losing
//! its typed source. Error storage is destroyed before its original credit.

use super::PackagedQemuExecutorError;
use crucible::owned_decode::DecodeScratch;
use std::error::Error;
use std::fmt;

/// Retains the original capture failure and its admitted owning storage.
pub struct PreparationExpiredCause {
    cause: Box<PackagedQemuExecutorError>,
    _resources: DecodeScratch,
}

impl PreparationExpiredCause {
    /// Returns the original launch, capture, or authentication failure.
    #[must_use]
    pub fn cause(&self) -> &PackagedQemuExecutorError {
        &self.cause
    }
}

impl fmt::Debug for PreparationExpiredCause {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.cause, formatter)
    }
}

impl fmt::Display for PreparationExpiredCause {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.cause, formatter)
    }
}

impl Error for PreparationExpiredCause {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.cause.as_ref())
    }
}

pub(super) fn finish_capture<T>(
    result: Result<T, PackagedQemuExecutorError>,
    expired: bool,
    resources: DecodeScratch,
) -> Result<T, PackagedQemuExecutorError> {
    if !expired {
        return result;
    }

    let source = result.err().map(|cause| PreparationExpiredCause {
        cause: Box::new(cause),
        _resources: resources,
    });
    Err(PackagedQemuExecutorError::PreparationExpired { source })
}

/// Keeps a private capture's actual failures under its original storage credit.
///
/// The owning body is freed before the external credit drops. Capture, watcher,
/// start and physical cleanup outcomes remain distinct; no concurrent total
/// order or native-retirement proof is inferred from a joined watcher.
#[cfg(feature = "private-measurement-domain")]
pub struct OriginalCaptureFailure {
    body: Box<OriginalCaptureFailureBody>,
    _resources: DecodeScratch,
}

#[cfg(feature = "private-measurement-domain")]
#[derive(Debug)]
pub(super) struct OriginalCaptureFailureBody {
    pub(super) capture: Option<PackagedQemuExecutorError>,
    pub(super) start: Option<crate::private_original_capture::OriginalCaptureStartError>,
    pub(super) completion: Option<crate::private_original_capture::OriginalCaptureCompletion>,
    pub(super) watcher: Option<crate::private_original_capture::OriginalCaptureWatcherRefusal>,
    pub(super) cleanup: Option<crucible_api::host_operational::HostOperationalError>,
    pub(super) configuration_original:
        Option<crucible_linux_resource::host_supervision::HostSupervisionError>,
    pub(super) release_original:
        Option<crucible_linux_resource::host_supervision::HostSupervisionError>,
}

#[cfg(feature = "private-measurement-domain")]
impl OriginalCaptureFailure {
    /// Returns the actual capture failure, when capture reached that outcome.
    #[must_use]
    pub fn capture(&self) -> Option<&PackagedQemuExecutorError> {
        self.body.capture.as_ref()
    }

    /// Returns the exact real watcher completion, if physical cleanup allowed a join.
    #[must_use]
    pub fn completion(&self) -> Option<crate::private_original_capture::OriginalCaptureCompletion> {
        self.body.completion
    }

    /// Returns the actual watcher-start refusal without replacing its source.
    #[must_use]
    pub fn start(&self) -> Option<&crate::private_original_capture::OriginalCaptureStartError> {
        self.body.start.as_ref()
    }

    /// Returns the first refusal actually recorded by the real watcher.
    #[must_use]
    pub fn watcher(
        &self,
    ) -> Option<crate::private_original_capture::OriginalCaptureWatcherRefusal> {
        self.body.watcher
    }

    /// Returns the separate original refusal after reserve/configure work.
    #[must_use]
    pub fn configuration_original(
        &self,
    ) -> Option<crucible_linux_resource::host_supervision::HostSupervisionError> {
        self.body.configuration_original
    }

    /// Returns the same original's refusal after the actual cleanup attempt.
    #[must_use]
    pub fn release_original(
        &self,
    ) -> Option<crucible_linux_resource::host_supervision::HostSupervisionError> {
        self.body.release_original
    }

    /// Returns the physical service's separate cleanup refusal.
    #[must_use]
    pub fn cleanup(&self) -> Option<&crucible_api::host_operational::HostOperationalError> {
        self.body.cleanup.as_ref()
    }
}

#[cfg(feature = "private-measurement-domain")]
impl fmt::Debug for OriginalCaptureFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.body, formatter)
    }
}

#[cfg(feature = "private-measurement-domain")]
impl fmt::Display for OriginalCaptureFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("private original capture did not accept completion")
    }
}

#[cfg(feature = "private-measurement-domain")]
impl Error for OriginalCaptureFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        if let Some(capture) = &self.body.capture {
            return Some(capture);
        }
        // Configuration's retained postcheck precedes watcher construction.
        // A later cleanup refusal must not replace this sole earlier cause.
        if let Some(original) = &self.body.configuration_original {
            return Some(original);
        }
        if let Some(start) = &self.body.start {
            return Some(start);
        }
        if let Some(watcher) = &self.body.watcher {
            return Some(match watcher {
                crate::private_original_capture::OriginalCaptureWatcherRefusal::Original(
                    source,
                )
                | crate::private_original_capture::OriginalCaptureWatcherRefusal::CaptureWait {
                    source,
                    ..
                } => source,
            });
        }
        if let Some(completion) = &self.body.completion {
            // These are the synchronous finish cuts, not a claimed total
            // order among capture work and a concurrently running watcher.
            if let Some(original) = &completion.original_before {
                return Some(original);
            }
            if let Some(child) = &completion.child {
                return Some(child);
            }
            if let Some(original) = &completion.original_after {
                return Some(original);
            }
        }
        if let Some(cleanup) = &self.body.cleanup {
            return Some(cleanup);
        }
        self.body
            .release_original
            .as_ref()
            .map(|source| source as &(dyn Error + 'static))
    }
}

#[cfg(feature = "private-measurement-domain")]
pub(super) fn original_failure(
    body: OriginalCaptureFailureBody,
    resources: DecodeScratch,
) -> PackagedQemuExecutorError {
    OriginalCaptureFailure {
        body: Box::new(body),
        _resources: resources,
    }
    .into()
}

#[cfg(feature = "private-measurement-domain")]
pub(super) fn finish_original_capture<T>(
    result: Result<T, PackagedQemuExecutorError>,
    completion: crate::private_original_capture::OriginalCaptureCompletion,
    cleanup: Option<crucible_api::host_operational::HostOperationalError>,
    release_original: Option<crucible_linux_resource::host_supervision::HostSupervisionError>,
    resources: DecodeScratch,
) -> Result<T, PackagedQemuExecutorError> {
    if completion.accepted() && cleanup.is_none() && release_original.is_none() {
        return result;
    }
    Err(original_failure(
        OriginalCaptureFailureBody {
            capture: result.err(),
            start: None,
            completion: Some(completion),
            watcher: completion.watcher,
            cleanup,
            configuration_original: None,
            release_original,
        },
        resources,
    ))
}

#[cfg(test)]
#[path = "failure/tests.rs"]
mod tests;
