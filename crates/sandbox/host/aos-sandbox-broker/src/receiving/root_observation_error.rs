//! Preserves fixed Root observation classifications below role orchestration.
//!
//! Owning startup-continuation failures remain in the upper role. These fixed
//! projections carry no success capability; actual IO/decoder failures remain
//! on their reached native capture fields.

use crate::profile_data::{ControllerProfileErrorV1, images};

/// Classifies a failed fixed Root native observation without carrying authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RootObservationErrorV1 {
    /// The actual original descriptor table is absent or malformed.
    #[error("normal Root original startup table differs")]
    Activation,
    /// The actual immutable Root profile differs.
    #[error("normal Root immutable profile differs")]
    Profile,
    /// The actual immutable Root image differs.
    #[error("normal Root actual immutable image differs")]
    Image,
    /// The actual fixed Root service custody differs.
    #[error("normal Root actual fixed-unit custody differs")]
    Service,
    /// The actual Root confinement differs.
    #[error("normal Root actual confinement differs")]
    Confinement,
}

impl From<ControllerProfileErrorV1> for RootObservationErrorV1 {
    fn from(error: ControllerProfileErrorV1) -> Self {
        match error {
            ControllerProfileErrorV1::Activation => Self::Activation,
            ControllerProfileErrorV1::Profile => Self::Profile,
            ControllerProfileErrorV1::Image => Self::Image,
            ControllerProfileErrorV1::Service => Self::Service,
            ControllerProfileErrorV1::Confinement => Self::Confinement,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub(super) enum RootImageObservationErrorV1 {
    #[error("selected profile shape differs")]
    Profile(#[from] RootObservationErrorV1),
    #[error("selected original file observation failed")]
    Io(#[from] std::io::Error),
    #[error("selected original descriptor inspection failed")]
    Descriptor(#[from] rustix::io::Errno),
    #[error("selected immutable measurement differs")]
    Image(#[from] crate::immutable_image::ImmutableImageErrorV1),
}

impl From<images::ImageObservationErrorV1> for RootImageObservationErrorV1 {
    fn from(error: images::ImageObservationErrorV1) -> Self {
        match error {
            images::ImageObservationErrorV1::Profile(error) => Self::Profile(error.into()),
            images::ImageObservationErrorV1::Io(error) => Self::Io(error),
            images::ImageObservationErrorV1::Descriptor(error) => Self::Descriptor(error),
            images::ImageObservationErrorV1::Image(error) => Self::Image(error),
        }
    }
}
