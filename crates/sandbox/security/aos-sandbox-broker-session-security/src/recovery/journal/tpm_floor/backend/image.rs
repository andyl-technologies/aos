//! Adapts shared fixed-helper measurement to the private floor roles.
//!
//! Broker owns the passive image, pin and native-prefix engine. This facade
//! selects only the existing normal purpose and keeps Security's redacted error
//! categories and PID1 launch admission local. Measurement grants no authority.

use std::error::Error;
use std::path::Path;

use aos_sandbox_broker::fixed_tpm_helper_image as shared;
use aos_sandbox_model::ResourceVector;

use super::super::FloorErrorV1;

pub(super) use crate::immutable_image::RetainedImmutableFileV1 as MeasuredFileV1;

use shared::FixedTpmHelperPurposeV1 as Purpose;
pub(crate) use shared::{HelperExecutedImageOriginalV1, HelperImageRevalidationOriginalV1};

pub(crate) struct MeasuredHelperImageV1(shared::MeasuredHelperImageV1);

impl MeasuredHelperImageV1 {
    pub(crate) fn open() -> Result<Self, FloorErrorV1> {
        shared::MeasuredHelperImageV1::open(Purpose::Broker)
            .map(Self)
            .map_err(Into::into)
    }

    pub(crate) fn open_runtime_deployment() -> Result<Self, FloorErrorV1> {
        shared::MeasuredHelperImageV1::open(Purpose::RuntimeDeployment)
            .map(Self)
            .map_err(Into::into)
    }

    pub(crate) fn open_online(
        role: crate::tpm_nv_custody::OnlineFloorRoleV1,
    ) -> Result<Self, FloorErrorV1> {
        let purpose = match role {
            crate::tpm_nv_custody::OnlineFloorRoleV1::Controller => Purpose::ControllerNix,
            crate::tpm_nv_custody::OnlineFloorRoleV1::Owner => Purpose::NixOwner,
        };
        shared::MeasuredHelperImageV1::open(purpose)
            .map(Self)
            .map_err(Into::into)
    }

    pub(crate) fn path(&self) -> &Path {
        self.0.path()
    }

    pub(crate) fn require_executed(&self, pid: u32) -> Result<(), FloorErrorV1> {
        self.0.require_executed(pid).map_err(Into::into)
    }

    pub(crate) fn require_executed_retaining_v1(
        &self,
        pid: u32,
        original: &mut HelperExecutedImageOriginalV1,
    ) -> Result<(), FloorErrorV1> {
        self.0
            .require_executed_retaining_v1(pid, original)
            .map_err(Into::into)
    }

    pub(crate) fn revalidate(&mut self) -> Result<(), FloorErrorV1> {
        self.0.revalidate().map_err(Into::into)
    }

    pub(crate) fn revalidation_receiving_demand_v1(&self) -> Option<ResourceVector> {
        self.0.revalidation_receiving_demand_v1()
    }

    pub(crate) fn revalidate_primary_retaining_v1(
        &self,
        original: &mut HelperImageRevalidationOriginalV1,
    ) -> Result<(), FloorErrorV1> {
        self.0
            .revalidate_primary_retaining_v1(original)
            .map_err(Into::into)
    }

    pub(crate) fn revalidate_owed_retaining_v1(
        &self,
        original: &mut HelperImageRevalidationOriginalV1,
    ) -> Result<(), FloorErrorV1> {
        self.0
            .revalidate_owed_retaining_v1(original)
            .map_err(Into::into)
    }

    pub(crate) fn drain_owed_after_unwind_once_v1(
        &self,
        original: &mut HelperImageRevalidationOriginalV1,
    ) -> Result<(), FloorErrorV1> {
        self.0
            .drain_owed_after_unwind_once_v1(original)
            .map_err(Into::into)
    }
}

pub(crate) struct HelperImageAcquisitionOriginalV1(shared::HelperImageAcquisitionOriginalV1);

impl HelperImageAcquisitionOriginalV1 {
    pub(crate) fn new() -> Self {
        Self(shared::HelperImageAcquisitionOriginalV1::new())
    }

    pub(crate) fn capture_once(&mut self) -> Result<(), FloorErrorV1> {
        self.0.capture_once(Purpose::Broker).map_err(Into::into)
    }

    pub(crate) fn capture_runtime_deployment_once(&mut self) -> Result<(), FloorErrorV1> {
        self.0
            .capture_once(Purpose::RuntimeDeployment)
            .map_err(Into::into)
    }

    pub(crate) fn take_completed_once(&mut self) -> Option<MeasuredHelperImageV1> {
        self.0.take_completed_once().map(MeasuredHelperImageV1)
    }

    pub(crate) fn receiving_demand_v1() -> Option<ResourceVector> {
        shared::HelperImageAcquisitionOriginalV1::receiving_demand_v1(Purpose::Broker)
    }

    pub(crate) fn runtime_deployment_receiving_demand_v1() -> Option<ResourceVector> {
        shared::HelperImageAcquisitionOriginalV1::receiving_with_input_demand_v1(
            Purpose::RuntimeDeployment,
        )
    }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.0.failure()
    }
}

/// Retains the original PID1 file against the existing backend image pin.
pub(super) fn open_original_pid1_image(
    launch_image: &crate::production_startup::Pid1LaunchImageV1,
) -> Result<crate::immutable_image::RetainedImmutableFileV1, FloorErrorV1> {
    let original = launch_image
        .file()
        .map_err(|_| FloorErrorV1::Provisioning)?;
    aos_sandbox_broker::immutable_image::retain_original_backend_pid1_v1(original)
        .map_err(Into::into)
}

impl From<crate::immutable_image::ImmutableImageErrorV1> for FloorErrorV1 {
    fn from(error: crate::immutable_image::ImmutableImageErrorV1) -> Self {
        match error {
            crate::immutable_image::ImmutableImageErrorV1::Unavailable => Self::Unavailable,
            crate::immutable_image::ImmutableImageErrorV1::Provisioning => Self::Provisioning,
        }
    }
}
