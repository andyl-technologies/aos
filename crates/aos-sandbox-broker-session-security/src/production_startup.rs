//! Closed startup tables for the two existing method-46 floor owners.
//!
//! The original PID 1 image is observed only through the fixed unit's named
//! `OpenFile=/proc/1/exe:aos-method46-pid1-image:read-only` entry. Environment
//! names select slots, not authority. This module exposes no caller-supplied
//! FD/image constructor. The floor's measured-image and genuine-manager guard
//! independently validate this parent-only observation before any TPM use.

use std::fs::File;
use std::os::fd::OwnedFd;
use std::path::Path;
use std::sync::Arc;

use aos_sandbox::normal_root::{
    ControllerInitialCaptureFailureRefV1, ProductionControllerInitialCaptureAttemptV1,
    ProductionControllerNormalRootCaptureV1, ProductionControllerNormalRootProfileV1,
    ProductionControllerNormalRootStartupPartsV1,
};
use aos_sandbox_linux::seqpacket::RecordSubjectListener;
use aos_sandbox_storage::activation::take_systemd_startup;
use aos_sandbox_storage::service::StorageServiceError;

use crate::{ProductionBrokerSessionActivationV1, ProtectedBrokerSessionFixedEndpointV1};

/// Retains an original launch observation, not a currentness or TPM proof.
#[derive(Clone)]
pub(crate) struct Pid1LaunchImageV1 {
    endpoint: ProtectedBrokerSessionFixedEndpointV1,
    process: u32,
    file: LaunchImageFile,
    profile_delivery: ControllerProfileDeliveryV1,
}

// Legacy keeps its literal allocation interval. The retained destination is
// empty BEFORE capture and receives only the same actual original afterward.
#[derive(Clone)]
enum LaunchImageFile {
    Legacy(Arc<File>),
    Retained(Arc<Option<File>>),
}

// Pending capture cannot stand in for genuinely admitted profile absence.
#[derive(Clone)]
enum ControllerProfileDeliveryV1 {
    Storage,
    Pending,
    Admitted(Option<Arc<ProductionControllerNormalRootProfileV1>>),
}

impl Pid1LaunchImageV1 {
    pub(crate) fn require_endpoint(
        &self,
        endpoint: ProtectedBrokerSessionFixedEndpointV1,
    ) -> Result<(), crate::BrokerSessionSecurityError> {
        let admitted_role = matches!(
            (&self.profile_delivery, endpoint),
            (
                ControllerProfileDeliveryV1::Storage,
                ProtectedBrokerSessionFixedEndpointV1::StorageBroker
            ) | (
                ControllerProfileDeliveryV1::Admitted(_),
                ProtectedBrokerSessionFixedEndpointV1::ControllerStorageClient
            )
        );
        if self.endpoint != endpoint || self.process != std::process::id() || !admitted_role {
            return Err(crate::BrokerSessionSecurityError::Currentness);
        }
        Ok(())
    }

    // The actual startup caller binds only its consumed admit_selected result.
    pub(crate) fn bind_controller_profile(
        mut self,
        profile: Option<Arc<ProductionControllerNormalRootProfileV1>>,
    ) -> Result<Self, crate::BrokerSessionSecurityError> {
        if self.endpoint != ProtectedBrokerSessionFixedEndpointV1::ControllerStorageClient
            || self.process != std::process::id()
            || !matches!(&self.profile_delivery, ControllerProfileDeliveryV1::Pending)
        {
            return Err(crate::BrokerSessionSecurityError::Currentness);
        }
        if let Some(profile) = &profile {
            profile
                .recheck()
                .map_err(|_| crate::BrokerSessionSecurityError::Currentness)?;
        }
        self.profile_delivery = ControllerProfileDeliveryV1::Admitted(profile);
        Ok(self)
    }

    pub(crate) fn recheck_profile_delivery(
        &self,
        endpoint: ProtectedBrokerSessionFixedEndpointV1,
    ) -> Result<Option<&Path>, crate::BrokerSessionSecurityError> {
        self.require_endpoint(endpoint)?;
        match &self.profile_delivery {
            ControllerProfileDeliveryV1::Admitted(Some(profile)) => {
                profile
                    .recheck()
                    .map_err(|_| crate::BrokerSessionSecurityError::Currentness)?;
                Ok(Some(profile.profile_path()))
            }
            ControllerProfileDeliveryV1::Storage | ControllerProfileDeliveryV1::Admitted(None) => {
                Ok(None)
            }
            ControllerProfileDeliveryV1::Pending => {
                Err(crate::BrokerSessionSecurityError::Currentness)
            }
        }
    }

    /// Borrows the same original launch image without another observation.
    ///
    /// # Errors
    ///
    /// Returns `Currentness` when a retained destination has no original file,
    /// before image measurement. Legacy images always return their original.
    pub(crate) fn file(&self) -> Result<&File, crate::BrokerSessionSecurityError> {
        match &self.file {
            LaunchImageFile::Legacy(file) => Ok(file.as_ref()),
            LaunchImageFile::Retained(slot) => slot
                .as_ref()
                .as_ref()
                .ok_or(crate::BrokerSessionSecurityError::Currentness),
        }
    }
}

/// Retains all existing Storage listeners and its private launch observation.
///
/// Construction captures the actual process-start table; it accepts no caller
/// descriptor or image claim. The image never leaves the parent floor owner.
pub struct ProductionStorageStartupV1 {
    activation: ProductionBrokerSessionActivationV1,
    export: RecordSubjectListener,
    live_export: Option<RecordSubjectListener>,
    zfs_hold: Option<RecordSubjectListener>,
    operator: Option<RecordSubjectListener>,
    existing_output: Option<RecordSubjectListener>,
}

/// Storage activation and its separately retained non-broker listeners.
pub type ProductionStorageStartupPartsV1 = (
    ProductionBrokerSessionActivationV1,
    RecordSubjectListener,
    Option<RecordSubjectListener>,
    Option<RecordSubjectListener>,
    Option<RecordSubjectListener>,
    Option<RecordSubjectListener>,
);

impl ProductionStorageStartupV1 {
    /// Captures the closed table before opening any retained service state.
    ///
    /// # Errors
    ///
    /// Rejects invalid activation, mismatched immutable floor mode/image
    /// presence, or any fixed broker-listener failure. This cannot be retried.
    pub fn capture() -> Result<Self, StorageServiceError> {
        let (listeners, image) = take_systemd_startup()?.into_parts();
        Self::admit_captured_parts(listeners, image)
    }

    /// Captures once and transfers genuine original worker startup downward.
    ///
    /// The existing six-listener tuple and separate method-46 launch owner are
    /// unchanged. Missing original image yields no worker owner, not a grant.
    ///
    /// # Errors
    ///
    /// Rejects the same legacy activation/mode failures or typed original
    /// startup admission failures, retaining admitted worker custody on error.
    pub fn capture_original_worker_startup(
    ) -> Result<
        (
            Self,
            Option<aos_sandbox_storage::activation::StorageOriginalWorkerStartupV3>,
        ),
        aos_sandbox_storage::activation::StorageOriginalWorkerStartupErrorV3,
    > {
        use aos_sandbox_storage::activation::StorageOriginalWorkerStartupErrorV3;

        let captured = take_systemd_startup()?;
        let (listeners, image, startup) = captured.into_original_worker_parts()?;
        let startup_owner = match Self::admit_captured_parts(listeners, image) {
            Ok(owner) => owner,
            Err(error) => {
                return Err(StorageOriginalWorkerStartupErrorV3::retain_service_failure(
                    error,
                    startup,
                ));
            }
        };
        Ok((startup_owner, startup))
    }

    // Both capture paths consume the same complete table through the original
    // image-mode and fixed-listener admission sequence, without a second scan.
    fn admit_captured_parts(
        listeners: aos_sandbox_storage::activation::StorageSystemdListenersV1,
        image: Option<OwnedFd>,
    ) -> Result<Self, StorageServiceError> {
        let (control, export, live_export, zfs_hold, operator, existing_output) = listeners;
        let endpoint = ProtectedBrokerSessionFixedEndpointV1::StorageBroker;
        let image = admit_launch_observation(endpoint, image)
            .map_err(|_| startup_error("Storage launch image differs from image floor mode"))?;
        let mut activation = ProductionBrokerSessionActivationV1::adopt_storage_listener(control)
            .map_err(|error| startup_error(error.to_string()))?;
        activation.retain_launch_image(image);
        Ok(Self {
            activation,
            export,
            live_export,
            zfs_hold,
            operator,
            existing_output,
        })
    }

    /// Transfers the fixed activation and every existing sidecar listener.
    #[must_use]
    pub fn into_parts(self) -> ProductionStorageStartupPartsV1 {
        (
            self.activation,
            self.export,
            self.live_export,
            self.zfs_hold,
            self.operator,
            self.existing_output,
        )
    }
}

pub(crate) fn capture_controller(
    publisher: bool,
) -> Result<
    (
        Option<OwnedFd>,
        Option<Pid1LaunchImageV1>,
        aos_sandbox::normal_root::ProductionControllerNormalRootCaptureV1,
    ),
    crate::BrokerSessionSecurityError,
> {
    let captured = capture_controller_with_backends(publisher, false, false)?;
    Ok((captured.publisher_descriptor, captured.launch_image, captured.normal_root_capture))
}

pub(crate) struct CapturedControllerStartupV1 {
    pub(crate) publisher_descriptor: Option<OwnedFd>,
    pub(crate) launch_image: Option<Pid1LaunchImageV1>,
    pub(crate) normal_root_capture: aos_sandbox::normal_root::ProductionControllerNormalRootCaptureV1,
    pub(crate) nix_capture: Option<aos_sandbox::normal_root::ProductionControllerNixStartupCaptureV1>,
    pub(crate) git_source_listener: Option<OwnedFd>,
}

pub(crate) fn capture_controller_with_backends(
    publisher: bool,
    nix_enabled: bool,
    git_source_cut: bool,
) -> Result<CapturedControllerStartupV1, crate::BrokerSessionSecurityError> {
    let (mut profile, publisher_fd, image) =
        aos_sandbox::normal_root::ProductionControllerNormalRootCaptureV1::capture_with_backends(
            publisher, nix_enabled, git_source_cut,
        ).map_err(|_| crate::BrokerSessionSecurityError::Currentness)?;
    let nix_capture = profile.take_nix_startup();
    let git_source_listener = profile.take_git_source_listener();
    let image = admit_launch_observation(
        ProtectedBrokerSessionFixedEndpointV1::ControllerStorageClient,
        image,
    )?;
    Ok(CapturedControllerStartupV1 {
        publisher_descriptor: publisher_fd,
        launch_image: image,
        normal_root_capture: profile,
        nix_capture,
        git_source_listener,
    })
}

fn admit_launch_observation(
    endpoint: ProtectedBrokerSessionFixedEndpointV1,
    descriptor: Option<OwnedFd>,
) -> Result<Option<Pid1LaunchImageV1>, crate::BrokerSessionSecurityError> {
    let profile_delivery = launch_profile_delivery(endpoint, descriptor.is_some())?;
    Ok(descriptor.map(|descriptor| Pid1LaunchImageV1 {
        endpoint,
        process: std::process::id(),
        file: LaunchImageFile::Legacy(Arc::new(File::from(descriptor))),
        profile_delivery,
    }))
}

fn launch_profile_delivery(
    endpoint: ProtectedBrokerSessionFixedEndpointV1,
    supplied: bool,
) -> Result<ControllerProfileDeliveryV1, crate::BrokerSessionSecurityError> {
    crate::recovery::require_launch_image_presence(endpoint, supplied)?;
    match endpoint {
        ProtectedBrokerSessionFixedEndpointV1::ControllerStorageClient => {
            Ok(ControllerProfileDeliveryV1::Pending)
        }
        ProtectedBrokerSessionFixedEndpointV1::StorageBroker => {
            Ok(ControllerProfileDeliveryV1::Storage)
        }
        _ => Err(crate::BrokerSessionSecurityError::Currentness),
    }
}

/// Borrows a cause from the same nested retained startup owner.
///
/// The view is short and by value; Security stores no self-borrow or cloned
/// Core cause. It grants no launch, selected-profile or floor authority.
pub(crate) enum ControllerStartupFailureRefV1<'attempt> {
    Core(ControllerInitialCaptureFailureRefV1<'attempt>),
    Launch(&'attempt crate::BrokerSessionSecurityError),
    Closed,
}

impl std::fmt::Debug for ControllerStartupFailureRefV1<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Core(_) => "original Controller capture refused",
            Self::Launch(_) => "original Controller launch delivery refused",
            Self::Closed => "original Controller startup closed",
        })
    }
}

enum StartupCaptureFailure {
    Core,
    Launch(crate::BrokerSessionSecurityError),
    Closed,
}

/// Keeps actual startup originals resident across launch-presence admission.
///
/// The empty image destination is allocated before initial capture, never
/// after an original has left its slot. No installed caller migrates here.
/// Failed/abandoned or unwinding attempts abort before field release; OS death
/// is not drain or Source-flight settlement. Lower unreturned custody remains
/// a separate functional prerequisite.
#[must_use]
pub(crate) struct ControllerStartupCaptureAttemptV1 {
    image_destination: Arc<Option<File>>,
    core: ProductionControllerInitialCaptureAttemptV1,
    parts: Option<ProductionControllerNormalRootStartupPartsV1>,
    nix: Option<aos_sandbox::normal_root::ProductionControllerNixStartupCaptureV1>,
    git: Option<OwnedFd>,
    completed: Option<CapturedControllerStartupV1>,
    attempted: bool,
    failure: Option<StartupCaptureFailure>,
    armed: bool,
}

impl ControllerStartupCaptureAttemptV1 {
    pub(crate) fn new(publisher: bool, nix_enabled: bool, git_source_cut: bool) -> Self {
        // This is the sole retained-only allocation. It precedes any table IO
        // and contains no File, fabricated image or authorization claim.
        let image_destination = Arc::new(None);
        Self {
            image_destination,
            core: ProductionControllerNormalRootCaptureV1::begin_retained_capture(
                publisher, nix_enabled, git_source_cut,
            ),
            parts: None,
            nix: None,
            git: None,
            completed: None,
            attempted: false,
            failure: None,
            armed: true,
        }
    }

    /// Captures and checks the same originals once, before any journal opens.
    ///
    /// # Errors
    /// Borrows the actual nested Core or launch cause without releasing partial
    /// originals. Repeats are closed and perform no observations.
    pub(crate) fn capture_once(&mut self) -> Result<(), ControllerStartupFailureRefV1<'_>> {
        if self.attempted {
            self.failure.get_or_insert(StartupCaptureFailure::Closed);
        } else {
            self.attempted = true;
            let result = {
                let _unwind = AbortStartupCaptureUnwind;
                self.capture_body()
            };
            match result {
                Ok(()) => return Ok(()),
                Err(cause) => {
                    self.failure.get_or_insert(cause);
                }
            }
        }
        Err(self.failure_view())
    }

    pub(crate) fn first_failure(&self) -> Option<ControllerStartupFailureRefV1<'_>> {
        self.failure.as_ref().map(|_| self.failure_view())
    }

    /// Moves the same completed startup once without observation or allocation.
    ///
    /// The destination must be parked before a fallible continuation. Its Core
    /// capture can then enter the genuine existing retained-profile producer.
    pub(crate) fn take_completed_startup(&mut self) -> Option<CapturedControllerStartupV1> {
        if self.failure.is_some()
            || self.completed.is_none()
            || self.parts.is_some()
            || self.nix.is_some()
            || self.git.is_some()
        {
            return None;
        }
        let completed = self.completed.take();
        self.armed = false;
        completed
    }

    fn failure_view(&self) -> ControllerStartupFailureRefV1<'_> {
        match &self.failure {
            Some(StartupCaptureFailure::Core) => match self.core.first_failure() {
                Some(cause) => ControllerStartupFailureRefV1::Core(cause),
                None => ControllerStartupFailureRefV1::Closed,
            },
            Some(StartupCaptureFailure::Launch(cause)) => {
                ControllerStartupFailureRefV1::Launch(cause)
            }
            Some(StartupCaptureFailure::Closed) | None => ControllerStartupFailureRefV1::Closed,
        }
    }

    fn capture_body(&mut self) -> Result<(), StartupCaptureFailure> {
        if self.parts.is_some() || self.nix.is_some() || self.git.is_some()
            || self.completed.is_some()
        {
            return Err(StartupCaptureFailure::Closed);
        }
        if self.core.capture_once().is_err() {
            return Err(StartupCaptureFailure::Core);
        }
        let Some(parts) = self.core.take_completed_parts() else {
            return Err(StartupCaptureFailure::Closed);
        };
        self.parts = Some(parts);
        let parts = self.parts.as_mut().ok_or(StartupCaptureFailure::Closed)?;
        self.nix = parts.0.take_nix_startup();
        self.git = parts.0.take_git_source_listener();

        let endpoint = ProtectedBrokerSessionFixedEndpointV1::ControllerStorageClient;
        let image_present = parts.2.is_some();
        let profile_delivery = launch_profile_delivery(endpoint, image_present)
            .map_err(StartupCaptureFailure::Launch)?;

        // Check unique ownership and the empty destination BEFORE taking the
        // raw original. This borrow cannot allocate or observe another image.
        let target = Arc::get_mut(&mut self.image_destination)
            .ok_or(StartupCaptureFailure::Closed)?;
        if target.is_some() || parts.2.is_some() != image_present {
            return Err(StartupCaptureFailure::Closed);
        }
        if let Some(original) = parts.2.take() {
            *target = Some(File::from(original));
        }
        let launch_image = if image_present {
            Some(Pid1LaunchImageV1 {
                endpoint,
                process: std::process::id(),
                file: LaunchImageFile::Retained(Arc::clone(&self.image_destination)),
                profile_delivery,
            })
        } else {
            None
        };

        // The image is already resident in the shared original destination.
        // No observation/allocation follows any startup tuple removal.
        if self.completed.is_some()
            || self.parts.as_ref().is_none_or(|parts| parts.2.is_some())
        {
            return Err(StartupCaptureFailure::Closed);
        }
        let originals = self.parts.take();
        match originals {
            Some((normal_root_capture, publisher_descriptor, None)) => {
                self.completed = Some(CapturedControllerStartupV1 {
                    publisher_descriptor,
                    launch_image,
                    normal_root_capture,
                    nix_capture: self.nix.take(),
                    git_source_listener: self.git.take(),
                });
                Ok(())
            }
            parts => {
                self.parts = parts;
                // The shared original image never left image_destination.
                Err(StartupCaptureFailure::Closed)
            }
        }
    }
}

impl Drop for ControllerStartupCaptureAttemptV1 {
    fn drop(&mut self) {
        if self.armed {
            std::process::abort();
        }
    }
}

struct AbortStartupCaptureUnwind;

impl Drop for AbortStartupCaptureUnwind {
    fn drop(&mut self) {
        if std::thread::panicking() {
            std::process::abort();
        }
    }
}

fn startup_error(message: impl Into<String>) -> StorageServiceError {
    StorageServiceError::Activation(message.into())
}

#[cfg(test)]
mod retained_destination_tests {
    use super::*;

    #[test]
    fn an_empty_destination_is_unique_before_any_original_exists() {
        let mut destination: Arc<Option<File>> = Arc::new(None);

        let slot = Arc::get_mut(&mut destination);

        assert!(matches!(slot, Some(None)));
    }

    #[test]
    fn a_shared_empty_destination_cannot_receive_an_original() {
        let mut destination: Arc<Option<File>> = Arc::new(None);
        let retained = Arc::clone(&destination);

        let slot = Arc::get_mut(&mut destination);

        assert!(slot.is_none());
        assert!(destination.as_ref().is_none());
        assert!(retained.as_ref().is_none());
    }
}
