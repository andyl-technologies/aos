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

use aos_sandbox::normal_root::ProductionControllerNormalRootProfileV1;
use aos_sandbox_linux::seqpacket::RecordSubjectListener;
use aos_sandbox_storage::activation::take_systemd_startup;
use aos_sandbox_storage::service::StorageServiceError;

use crate::{ProductionBrokerSessionActivationV1, ProtectedBrokerSessionFixedEndpointV1};

/// Retains an original launch observation, not a currentness or TPM proof.
#[derive(Clone)]
pub(crate) struct Pid1LaunchImageV1 {
    endpoint: ProtectedBrokerSessionFixedEndpointV1,
    process: u32,
    file: Arc<File>,
    profile_delivery: ControllerProfileDeliveryV1,
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

    pub(crate) fn file(&self) -> &File {
        &self.file
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
    crate::recovery::require_launch_image_presence(endpoint, descriptor.is_some())?;
    let profile_delivery = match endpoint {
        ProtectedBrokerSessionFixedEndpointV1::ControllerStorageClient => {
            ControllerProfileDeliveryV1::Pending
        }
        ProtectedBrokerSessionFixedEndpointV1::StorageBroker => {
            ControllerProfileDeliveryV1::Storage
        }
        _ => return Err(crate::BrokerSessionSecurityError::Currentness),
    };
    Ok(descriptor.map(|descriptor| Pid1LaunchImageV1 {
        endpoint,
        process: std::process::id(),
        file: Arc::new(File::from(descriptor)),
        profile_delivery,
    }))
}

fn startup_error(message: impl Into<String>) -> StorageServiceError {
    StorageServiceError::Activation(message.into())
}
