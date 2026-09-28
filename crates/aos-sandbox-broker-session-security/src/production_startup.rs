//! Closed startup tables for the two existing method-46 floor owners.
//!
//! The original PID 1 image is observed only through the fixed unit's named
//! `OpenFile=/proc/1/exe:aos-method46-pid1-image:read-only` entry. Environment
//! names select slots, not authority. This module exposes no caller-supplied
//! FD/image constructor. The floor's measured-image and genuine-manager guard
//! independently validate this parent-only observation before any TPM use.

use std::fs::File;
use std::os::fd::OwnedFd;
use std::sync::Arc;

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
}

impl Pid1LaunchImageV1 {
    pub(crate) fn require_endpoint(
        &self,
        endpoint: ProtectedBrokerSessionFixedEndpointV1,
    ) -> Result<(), crate::BrokerSessionSecurityError> {
        if self.endpoint != endpoint || self.process != std::process::id() {
            return Err(crate::BrokerSessionSecurityError::Currentness);
        }
        Ok(())
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
    let (profile, publisher_fd, image) =
        aos_sandbox::normal_root::ProductionControllerNormalRootCaptureV1::capture(publisher)
            .map_err(|_| crate::BrokerSessionSecurityError::Currentness)?;
    let image = admit_launch_observation(
        ProtectedBrokerSessionFixedEndpointV1::ControllerStorageClient,
        image,
    )?;
    Ok((publisher_fd, image, profile))
}

fn admit_launch_observation(
    endpoint: ProtectedBrokerSessionFixedEndpointV1,
    descriptor: Option<OwnedFd>,
) -> Result<Option<Pid1LaunchImageV1>, crate::BrokerSessionSecurityError> {
    crate::recovery::require_launch_image_presence(endpoint, descriptor.is_some())?;
    Ok(descriptor.map(|descriptor| Pid1LaunchImageV1 {
        endpoint,
        process: std::process::id(),
        file: Arc::new(File::from(descriptor)),
    }))
}

fn startup_error(message: impl Into<String>) -> StorageServiceError {
    StorageServiceError::Activation(message.into())
}
