//! Adapts the same lower actual Root profile capture to role-owned startup.
//!
//! The genuine RootR/SourceF owner still pays before selecting its own inherited
//! descriptor. All actual file/model/decoder destinations now belong to one
//! lower engine; this adapter adds no parser, IO or successful authority.

use std::error::Error;
use std::os::fd::OwnedFd;

use aos_sandbox_core::ResourceVector;
use aos_sandbox_broker::receiving::{RootObservationErrorV1, RootProfileOriginalCaptureV1};

use crate::controller_resource_reservation::ResourceReservationErrorV1;
use crate::immutable_image::{ImmutableImageErrorV1, RetainedImmutableFileV1};
use super::{NormalRootStartupErrorV1, profile::NormalRootProfileV1};

#[derive(Default)]
pub(crate) struct RootProfileOriginalReceivingV1 {
    original: RootProfileOriginalCaptureV1,
}

impl RootProfileOriginalReceivingV1 {
    pub(crate) fn fixed_demand() -> Result<ResourceVector, ResourceReservationErrorV1> {
        RootProfileOriginalCaptureV1::fixed_demand()
            .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)
    }

    pub(crate) fn receive_original_once(
        &mut self,
        original: &mut Option<OwnedFd>,
    ) -> Result<(), NormalRootStartupErrorV1> {
        self.original.receive_original_once(original).map_err(Into::into)
    }

    pub(super) fn profile(&self) -> Option<&NormalRootProfileV1> {
        self.original.profile()
    }

    pub(super) fn measurement(&self) -> Result<&RetainedImmutableFileV1, ImmutableImageErrorV1> {
        self.original.measurement()
    }

    pub(super) fn recheck_source_original(&mut self) -> Result<(), NormalRootStartupErrorV1> {
        self.original.recheck_source_original().map_err(Into::into)
    }

    pub(super) fn take_originals(&mut self) -> Option<(RetainedImmutableFileV1, NormalRootProfileV1)> {
        self.original.take_originals()
    }

    pub(super) fn restore_originals(&mut self, originals: Option<(RetainedImmutableFileV1, NormalRootProfileV1)>) {
        self.original.restore_originals(originals);
    }

    pub(super) fn source_failure(&self) -> Option<&(dyn Error + 'static)> {
        self.original.source_failure()
    }

    pub(super) fn native_capture(&self) -> &RootProfileOriginalCaptureV1 {
        &self.original
    }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.original.failure()
    }
}

impl From<RootObservationErrorV1> for NormalRootStartupErrorV1 {
    fn from(error: RootObservationErrorV1) -> Self {
        match error {
            RootObservationErrorV1::Activation => Self::Activation,
            RootObservationErrorV1::Profile => Self::Profile,
            RootObservationErrorV1::Image => Self::Image,
            RootObservationErrorV1::Service => Self::Service,
            RootObservationErrorV1::Confinement => Self::Confinement,
        }
    }
}
