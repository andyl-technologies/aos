//! Projects the shared selected Controller custody into existing Root errors.
//!
//! Broker owns the same PID1 archive, images, cgroup and independent native
//! bookends. These private adapters add no sampler, admission or disposal path.

use std::error::Error as StdError;

use aos_sandbox_broker::receiving as native;
use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use aos_sandbox_linux::unix_stream::RetainedUnixStream;

use super::super::{NormalRootStartupErrorV1 as Error, ProductionNormalRootStartupV1};
use crate::controller_resource_reservation::{
    ResourceReservationErrorV1, service_interval::ObserverLifetime,
};

mod subject;
pub(crate) use subject::RootControllerChunkSubjectSampleV1;

pub(crate) struct RootControllerPeerReceivingV1<'startup> {
    native: native::RootSelectedControllerPeerOriginalV1<'startup>,
}

impl<'startup> RootControllerPeerReceivingV1<'startup> {
    pub(crate) fn new(
        startup: &'startup ProductionNormalRootStartupV1,
        lifetime: ObserverLifetime,
    ) -> Self {
        Self {
            native: native::RootSelectedControllerPeerOriginalV1::new(
                startup.native_startup_original_v1(),
                lifetime,
            ),
        }
    }

    pub(crate) fn fixed_demand() -> Result<ResourceVector, ResourceReservationErrorV1> {
        adapter_demand::<Self>(
            native::RootSelectedControllerPeerOriginalV1::fixed_demand()
                .map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?,
        )
    }

    pub(crate) fn capture_once(&mut self, stream: &RetainedUnixStream) -> Result<(), Error> {
        self.native.capture_once(stream).map_err(Into::into)
    }

    pub(crate) fn settle_positive_once(&mut self) -> Result<(), Error> {
        self.native.settle_positive_once().map_err(Into::into)
    }

    pub(crate) fn require_completed(&self) -> Result<(), Error> {
        self.native.require_completed().map_err(Into::into)
    }

    pub(crate) fn property_failure_view_v1(
        &self,
    ) -> Option<aos_systemd_client::FixedPid1PropertyFailureViewV1<'_>> {
        self.native.property_failure_view_v1()
    }

    pub(crate) fn failure(&self) -> Option<&(dyn StdError + 'static)> {
        self.native.failure()
    }

    pub(crate) fn observe_prearmed_current_into_v1(
        &self,
        stream: &RetainedUnixStream,
        sample: &mut RootControllerPeerCurrentSampleV1,
    ) -> Result<(), Error> {
        self.native
            .observe_prearmed_current_into_v1(stream, &mut sample.native)
            .map_err(Into::into)
    }

    pub(crate) fn native_original_v1(
        &self,
    ) -> &native::RootSelectedControllerPeerOriginalV1<'startup> {
        &self.native
    }
}

pub(crate) struct RootControllerPeerCurrentSampleV1 {
    native: native::RootSelectedControllerCurrentSampleV1,
}

// The adapter's construction, return and resident carriers coexist with the
// separately measured lower owner. Its real same-Root caller composes this
// passive byte supplier before construction; no namespace is created here.
fn adapter_demand<T>(native: ResourceVector) -> Result<ResourceVector, ResourceReservationErrorV1> {
    let invalid = || ResourceReservationErrorV1::EnrollmentUnavailable;
    let bytes = std::mem::size_of::<T>()
        .checked_mul(3)
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or_else(invalid)?;
    native
        .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes))
        .map_err(|_| invalid())
}

impl RootControllerPeerCurrentSampleV1 {
    pub(crate) fn demand_v1() -> Result<ResourceVector, ResourceReservationErrorV1> {
        adapter_demand::<Self>(
            native::RootSelectedControllerCurrentSampleV1::demand_v1()
                .map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?,
        )
    }

    pub(crate) fn new(lifetime: ObserverLifetime) -> Self {
        Self {
            native: native::RootSelectedControllerCurrentSampleV1::new(lifetime),
        }
    }

    pub(crate) fn settle_after_root_post_once_v1(&mut self) -> Result<(), Error> {
        self.native
            .settle_after_root_post_once_v1()
            .map_err(Into::into)
    }

    pub(crate) fn property_failure_view_v1(
        &self,
    ) -> Option<aos_systemd_client::FixedPid1PropertyFailureViewV1<'_>> {
        self.native.property_failure_view_v1()
    }

    pub(crate) fn failure(&self) -> Option<&(dyn StdError + 'static)> {
        self.native.failure()
    }
}
