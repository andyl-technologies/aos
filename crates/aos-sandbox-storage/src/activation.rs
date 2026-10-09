//! Exact systemd record-subject socket activation for `aos-storaged`.

mod original_worker;

pub(crate) use original_worker::StorageOriginalWorkerStartupCauseV3;
pub use original_worker::{StorageOriginalWorkerStartupErrorV3, StorageOriginalWorkerStartupV3};

use std::os::fd::OwnedFd;

use aos_sandbox::normal_root::{
    CapturedStorageLaunchV3, StorageLaunchCaptureErrorV3, StorageLaunchListenersV3,
    capture_storage_launch_v3,
};
pub use aos_sandbox::normal_root::storage_resource_recipient_selected_v1;

use crate::service::StorageServiceError;

/// Names the parent-only original PID 1 image delivered by fixed-unit OpenFile.
pub const PID1_LAUNCH_IMAGE_FD_NAME: &str =
    aos_sandbox::normal_root::PID1_LAUNCH_IMAGE_FD_NAME;

/// The fixed Storage listener roles, without any TPM or image authorization.
pub type StorageSystemdListenersV1 = StorageLaunchListenersV3;

/// Prearms selected resource-recipient custody without exposing its pair.
///
/// This is not a Project, floor or native-effect permission. Its only producer
/// consumes the complete actual inherited table through Core's sole engine.
#[must_use]
pub struct StorageResourceRecipientCaptureV1 {
    original: aos_sandbox::normal_root::StorageResourceRecipientCaptureV1,
}

impl StorageResourceRecipientCaptureV1 {
    /// Creates empty resident destinations before startup observation.
    pub const fn begin() -> Self {
        Self {
            original: aos_sandbox::normal_root::StorageResourceRecipientCaptureV1::begin(),
        }
    }

    /// Parks complete capture and its actual error before returning a status.
    pub fn capture_once(&mut self) -> bool {
        self.original.capture_once()
    }

    /// Parks the original Startup Result before independent component posts.
    pub fn admit_worker_once(&mut self) -> bool {
        self.original.admit_worker_once()
    }

    /// Borrows the earliest actual cause, never a portable paid marker.
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.original.failure()
    }

    /// Transfers only admitted startup roles, retaining the resource pair.
    ///
    /// # Errors
    ///
    /// Owns the complete failed recipient and partial Startup custody.
    pub fn into_original_worker_parts(self) -> Result<
        (StorageSystemdListenersV1, Option<OwnedFd>, Option<StorageOriginalWorkerStartupV3>),
        StorageOriginalWorkerStartupErrorV3,
    > {
        original_worker::admit_resource_recipient(self.original)
    }
}

/// Owns an observed complete startup table, not authenticated image custody.
pub struct CapturedStorageStartupV1 {
    original: CapturedStorageLaunchV3,
}

impl CapturedStorageStartupV1 {
    /// Returns observed listener roles and an unverified original launch image.
    #[must_use]
    pub fn into_parts(self) -> (StorageSystemdListenersV1, Option<OwnedFd>) {
        self.original.into_parts()
    }

    /// Admits worker startup custody from this one complete actual capture.
    ///
    /// The same original image remains available to the separate Security
    /// owner. Absence returns `None`, never an admitted empty image or grant.
    /// The returned opaque owner conveys no floor or backend readiness.
    ///
    /// # Errors
    ///
    /// Rejects changed actual process, unit, image, or confinement. Admission
    /// failure owns the original table and any partial retained observations.
    pub fn into_original_worker_parts(
        self,
    ) -> Result<
        (
            StorageSystemdListenersV1,
            Option<OwnedFd>,
            Option<StorageOriginalWorkerStartupV3>,
        ),
        StorageOriginalWorkerStartupErrorV3,
    > {
        original_worker::admit_captured(self)
    }
}

/// Adopts the required listeners and an optional closed Provider request listener.
///
/// # Errors
///
/// Rejects wrong PID, count, names, descriptor type, or missing record subjects.
pub fn take_systemd_listeners() -> Result<StorageSystemdListenersV1, StorageServiceError> {
    let (listeners, image) = take_systemd_startup()?.into_parts();
    if image.is_some() {
        return Err(activation_error(
            "legacy listener adoption cannot consume a PID 1 image",
        ));
    }
    Ok(listeners)
}

/// Captures fixed listeners and at most one observed parent-only image FD.
///
/// Every numeric entry is copied before opening any other retained descriptor.
/// Names and environment are correlation hints only. The security owner must
/// independently authenticate the fixed unit, image mode, and actual image.
///
/// # Errors
///
/// Rejects malformed names/counts, a nonclosed startup table, invalid listeners,
/// or an unknown descriptor. This single-shot operation cannot be retried.
pub fn take_systemd_startup() -> Result<CapturedStorageStartupV1, StorageServiceError> {
    capture_storage_launch_v3()
        .map(|original| CapturedStorageStartupV1 { original })
        .map_err(|error| match error {
            StorageLaunchCaptureErrorV3::Activation(message) => {
                StorageServiceError::Activation(message)
            }
            StorageLaunchCaptureErrorV3::Linux(error) => StorageServiceError::Kernel(error),
            StorageLaunchCaptureErrorV3::Transport(error) => StorageServiceError::Transport(error),
        })
}

fn activation_error(message: impl Into<String>) -> StorageServiceError {
    StorageServiceError::Activation(message.into())
}
