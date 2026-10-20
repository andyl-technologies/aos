//! Forwards shared image observations while preserving Root's error surface.

use std::fs::File;

use crate::immutable_image::{PendingImmutableFileV1, RetainedImmutableFileV1};
use aos_sandbox_broker::profile_data::images as shared;

use super::{NormalRootStartupErrorV1, profile::ImagePinV1};

#[derive(Debug, thiserror::Error)]
pub(super) enum ImageObservationErrorV1 {
    #[error("selected profile shape differs")]
    Profile(#[from] NormalRootStartupErrorV1),
    #[error("selected original file observation failed")]
    Io(#[from] std::io::Error),
    #[error("selected original descriptor inspection failed")]
    Descriptor(#[from] rustix::io::Errno),
    #[error("selected immutable measurement differs")]
    Image(#[from] crate::immutable_image::ImmutableImageErrorV1),
}

impl From<shared::ImageObservationErrorV1> for ImageObservationErrorV1 {
    fn from(error: shared::ImageObservationErrorV1) -> Self {
        match error {
            shared::ImageObservationErrorV1::Profile(error) => Self::Profile(error.into()),
            shared::ImageObservationErrorV1::Io(error) => Self::Io(error),
            shared::ImageObservationErrorV1::Descriptor(error) => Self::Descriptor(error),
            shared::ImageObservationErrorV1::Image(error) => Self::Image(error),
        }
    }
}

impl ImageObservationErrorV1 {
    pub(super) fn legacy_error(&self) -> NormalRootStartupErrorV1 {
        match self {
            Self::Profile(error) => match error {
                NormalRootStartupErrorV1::Activation => NormalRootStartupErrorV1::Activation,
                NormalRootStartupErrorV1::Profile => NormalRootStartupErrorV1::Profile,
                NormalRootStartupErrorV1::Image => NormalRootStartupErrorV1::Image,
                NormalRootStartupErrorV1::Service => NormalRootStartupErrorV1::Service,
                NormalRootStartupErrorV1::Confinement => NormalRootStartupErrorV1::Confinement,
                NormalRootStartupErrorV1::Receiving(_) => NormalRootStartupErrorV1::Service,
                NormalRootStartupErrorV1::SelectedCurrentness(_) => NormalRootStartupErrorV1::Service,
                NormalRootStartupErrorV1::ServiceReceiving(cause) => {
                    NormalRootStartupErrorV1::ServiceReceiving(std::sync::Arc::clone(cause))
                }
            },
            Self::Io(_) | Self::Descriptor(_) | Self::Image(_) => NormalRootStartupErrorV1::Image,
        }
    }

    pub(super) fn into_legacy(self) -> NormalRootStartupErrorV1 {
        match self {
            Self::Profile(error) => error,
            Self::Io(_) | Self::Descriptor(_) | Self::Image(_) => NormalRootStartupErrorV1::Image,
        }
    }
}

pub(super) fn retain_pin(pin: &ImagePinV1, original: Option<File>, executable: bool)
    -> Result<RetainedImmutableFileV1, NormalRootStartupErrorV1>
{
    shared::retain_pin(pin, original, executable).map_err(Into::into)
}

pub(super) fn park_original_pin(pin: &ImagePinV1, executable: bool, pending: &mut PendingImmutableFileV1)
    -> Result<(), ImageObservationErrorV1>
{
    shared::park_original_pin(pin, executable, pending).map_err(Into::into)
}

pub(super) fn retain_profile(file: File)
    -> Result<(RetainedImmutableFileV1, Vec<u8>), NormalRootStartupErrorV1>
{
    shared::retain_profile(file).map_err(Into::into)
}

pub(super) fn park_controller_profile(pending: &mut PendingImmutableFileV1)
    -> Result<(), ImageObservationErrorV1>
{
    shared::park_controller_profile(pending).map_err(Into::into)
}

pub(super) fn park_selected_pin(pin: &ImagePinV1, executable: bool, pending: &mut PendingImmutableFileV1)
    -> Result<(), ImageObservationErrorV1>
{
    shared::park_selected_pin(pin, executable, pending).map_err(Into::into)
}

pub(crate) fn require_actual_mappings(files: &[RetainedImmutableFileV1], required: &[&str])
    -> Result<(), NormalRootStartupErrorV1>
{
    shared::require_actual_mappings(files, required).map_err(Into::into)
}

pub(crate) fn require_executable_mapping_data_v2(files: &[RetainedImmutableFileV1], required: &[&str], maps: &str)
    -> Result<(), NormalRootStartupErrorV1>
{
    shared::require_executable_mapping_data_v2(files, required, maps).map_err(Into::into)
}
