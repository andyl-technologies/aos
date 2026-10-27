//! Retains Source's image-delivered Root comparison inputs under the same F.
//!
//! Only the genuine Source original lends the fixed inherited profile and
//! admits its two closed stages. The ordinary Root profile/image/policy engines
//! remain shared; no request tuple or historical signed row supplies an image.

use std::collections::TryReserveError;
use std::error::Error;
use std::path::Path;

use aos_sandbox_model::ResourceVector;
use aos_sandbox_broker::receiving::{RootPeerImageObservationsV1,
    RootPeerImageObservationErrorV1};
use aos_sandbox_linux::selinux_policy::PolicyReadbackError;

use crate::signer::{
    SourceReceivingGeometryErrorV1 as ResourceReservationErrorV1, SourceReceivingClosedV1, SourceRootPeerInputsLoanV1,
};
use aos_sandbox_broker::immutable_image::ImmutableImageErrorV1;

use aos_sandbox_broker::profile_data::{images, schema as profile};
use aos_sandbox_broker::receiving::{RootProfileOriginalCaptureV1 as RootProfileOriginalReceivingV1, RootObservationErrorV1 as NormalRootStartupErrorV1};

#[derive(Debug, thiserror::Error)]
enum InputError {
    #[error("Source Root inputs require their same original receiving loan")]
    Original(#[from] SourceReceivingClosedV1),
    #[error("Source Root input geometry is unavailable")]
    Geometry(#[from] ResourceReservationErrorV1),
    #[error("Source Root selected profile differs")]
    Profile(#[from] NormalRootStartupErrorV1),
    #[error("Source Root image observation failed")]
    Image(#[from] images::ImageObservationErrorV1),
    #[error("Source Root immutable input failed")]
    Immutable(#[from] ImmutableImageErrorV1),
    #[error("Source Root policy observation failed")]
    Policy(#[from] PolicyReadbackError),
    #[error("Source Root input carrier allocation failed")]
    Allocation(#[from] TryReserveError),
}

impl From<RootPeerImageObservationErrorV1> for InputError {
    fn from(cause: RootPeerImageObservationErrorV1) -> Self {
        match cause {
            RootPeerImageObservationErrorV1::Profile(cause) => Self::Profile(cause.into()),
            RootPeerImageObservationErrorV1::Image(cause) => Self::Image(cause.into()),
            RootPeerImageObservationErrorV1::Policy(cause) => Self::Policy(cause),
            RootPeerImageObservationErrorV1::Allocation(cause) => Self::Allocation(cause),
        }
    }
}

pub(crate) struct SourceRootPeerInputsV1 {
    profile: RootProfileOriginalReceivingV1,
    images: RootPeerImageObservationsV1,
    profile_stage: Option<Result<(), InputError>>,
    selected_stage: Option<Result<(), InputError>>,
    closed: Option<NormalRootStartupErrorV1>,
}

impl SourceRootPeerInputsV1 {
    pub(crate) fn new() -> Self {
        Self {
            profile: RootProfileOriginalReceivingV1::default(),
            images: RootPeerImageObservationsV1::new(),
            profile_stage: None, selected_stage: None, closed: None,
        }
    }

    // The actual Original calls this with its exclusive, privately made loan.
    // Both reservations happen before their respective allocating readers.
    pub(crate) fn receive_once(
        &mut self,
        loan: &mut SourceRootPeerInputsLoanV1<'_>,
    ) -> Result<(), SourceReceivingClosedV1> {
        if self.profile_stage.is_some() || self.selected_stage.is_some() {
            self.closed.get_or_insert(NormalRootStartupErrorV1::Activation);
            return Err(SourceReceivingClosedV1);
        }
        self.profile_stage = Some((|| {
            loan.reserve_profile_once()?;
            loan.move_profile_into(&mut self.profile)?;
            let profile = self.profile.profile().ok_or(NormalRootStartupErrorV1::Profile)?;
            loan.require_source_identity(&profile.identities)?;
            if self.profile.measurement()?.path().parent()
                != Path::new(&profile.effective_matrix.path).parent()
            {
                return Err(NormalRootStartupErrorV1::Profile.into());
            }
            Ok(())
        })());
        if !matches!(self.profile_stage, Some(Ok(()))) {
            return Err(SourceReceivingClosedV1);
        }
        self.selected_stage = Some((|| {
            loan.reserve_selected_once(self)?;
            let profile = self.profile.profile().ok_or(NormalRootStartupErrorV1::Profile)?;
            if self.images.observe_once(profile).is_err() {
                let cause = self.images.take_failure_once()
                    .ok_or(NormalRootStartupErrorV1::Image)?;
                return Err(cause.into());
            }
            Ok(())
        })());
        if self.complete() { Ok(()) } else { Err(SourceReceivingClosedV1) }
    }

    pub(crate) fn profile_demand() -> Result<ResourceVector, ResourceReservationErrorV1> {
        RootProfileOriginalReceivingV1::fixed_demand()
            .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)
    }

    // Paths/counts come from the actual bounded inherited model. No file body
    // is buffered here: each shared immutable engine hashes bounded chunks.
    pub(crate) fn selected_demand(&self) -> Result<ResourceVector, ResourceReservationErrorV1> {
        let error = || ResourceReservationErrorV1::EnrollmentUnavailable;
        let profile = self.profile.profile().ok_or_else(error)?;
        RootPeerImageObservationsV1::receiving_demand_v1(profile).ok_or_else(error)
    }

    pub(super) fn profile(&self) -> Result<&profile::NormalRootProfileV1, NormalRootStartupErrorV1> {
        if !self.complete() { return Err(NormalRootStartupErrorV1::Profile); }
        self.profile.profile().ok_or(NormalRootStartupErrorV1::Profile)
    }

    pub(super) fn profile_file(
        &self,
    ) -> Result<&aos_sandbox_broker::immutable_image::RetainedImmutableFileV1, ImmutableImageErrorV1> {
        self.profile.measurement()
    }

    // Each complete paid IO/observation stage uses this shared original input
    // set. Native first causes remain parked; successful fields stay resident.
    pub(super) fn recheck_images(&mut self) -> Result<(), NormalRootStartupErrorV1> {
        if !self.complete() { return Err(NormalRootStartupErrorV1::Profile); }
        self.profile.recheck_source_original()?;
        self.images.recheck_images().map_err(|_| NormalRootStartupErrorV1::Image)
    }

    pub(crate) fn controller_uid(&self) -> Result<u32, NormalRootStartupErrorV1> {
        Ok(self.profile()?.identities[0])
    }

    pub(crate) fn complete(&self) -> bool {
        self.closed.is_none() && matches!(self.profile_stage, Some(Ok(())))
            && matches!(self.selected_stage, Some(Ok(()))) && self.failure().is_none()
    }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        // A profile-stage refusal precedes all selected-stage acquisition.
        if let Some(Err(error)) = &self.profile_stage {
            return self.profile.source_failure().or(Some(error));
        }
        if let Some(Err(error)) = &self.selected_stage {
            return self.images.failure().or(Some(error));
        }
        self.profile.source_failure()
            .or_else(|| self.images.failure())
            .or_else(|| self.closed.as_ref().map(|error| error as _))
    }
}
