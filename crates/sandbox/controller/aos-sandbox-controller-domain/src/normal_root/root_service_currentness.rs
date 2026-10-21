//! Preserves the private Root role's classification over its actual sampler.

use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use aos_sandbox_broker::receiving::{RootInitialReceivingOriginalV1, RootServiceCurrentnessOriginalV1};
use crate::controller_resource_reservation::ResourceReservationErrorV1;
use super::{NormalRootStartupErrorV1, ProductionNormalRootStartupV1};

pub(crate) struct RootServiceCurrentnessV1 {
    result: Result<(), NormalRootStartupErrorV1>,
}

impl RootServiceCurrentnessV1 {
    pub(crate) fn demand() -> Result<ResourceVector, ResourceReservationErrorV1> {
        let invalid = || ResourceReservationErrorV1::EnrollmentUnavailable;
        let native = RootServiceCurrentnessOriginalV1::demand().ok_or_else(invalid)?;
        native.checked_add(Self::adapter_demand_v1()?).map_err(|_| invalid())
    }

    pub(crate) fn adapter_demand_v1() -> Result<ResourceVector, ResourceReservationErrorV1> {
        let invalid = || ResourceReservationErrorV1::EnrollmentUnavailable;
        let bytes = std::mem::size_of::<Self>().checked_mul(2)
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<ResourceVector>().checked_mul(4)?))
            .ok_or_else(invalid)?;
        let adapter = ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(bytes).map_err(|_| invalid())?);
        Ok(adapter)
    }

    pub(crate) fn observe_actual_once(
        original: &mut RootInitialReceivingOriginalV1,
        startup: &ProductionNormalRootStartupV1,
    ) -> Self {
        Self { result: original.observe_startup_currentness_once(&startup.native).map_err(Into::into) }
    }

    pub(crate) fn is_positive(&self) -> bool {
        self.result.is_ok()
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.result.as_ref().err().map(|cause| cause as &(dyn std::error::Error + 'static))
    }
}
