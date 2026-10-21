//! Projects the shared selected Controller custody into existing Root errors.
//!
//! Broker owns the same PID1 archive, images, cgroup and independent native
//! bookends. These private adapters add no sampler, admission or disposal path.

use std::error::Error as StdError;

use aos_sandbox_broker::receiving as native;
use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use aos_linux_descriptors::unix_stream::RetainedUnixStream;

use super::super::{NormalRootStartupErrorV1 as Error, ProductionNormalRootStartupV1};
use crate::controller_resource_reservation::{
    ResourceReservationErrorV1, service_interval::ObserverLifetime,
};

mod subject;
pub(crate) use subject::RootControllerChunkSubjectSampleV1;

pub(crate) struct RootControllerPeerReceivingV1<'startup> {
    native: RootControllerPeerStorageV1<'startup>,
}

enum RootControllerPeerStorageV1<'startup> {
    Initial(aos_sandbox_policy::native::RootStartupControllerPeerOriginalV1<'startup>),
    Purpose(native::RootSelectedControllerPeerOriginalV1<'startup>),
    // The same wrapper remains on Flight while its actual Initial producer is
    // owned by the native programme. This is never a completed peer variant.
    InitialTaken,
}

impl<'startup> RootControllerPeerReceivingV1<'startup> {
    pub(crate) fn new(
        startup: &'startup ProductionNormalRootStartupV1,
        lifetime: ObserverLifetime,
    ) -> Self {
        Self {
            native: RootControllerPeerStorageV1::Purpose(
                native::RootSelectedControllerPeerOriginalV1::new(
                    startup.native_startup_original_v1(),
                    lifetime,
                ),
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
        match &mut self.native {
            RootControllerPeerStorageV1::Initial(original) => original.capture_once_v1(stream),
            RootControllerPeerStorageV1::Purpose(original) => original.capture_once(stream),
            RootControllerPeerStorageV1::InitialTaken => return Err(Error::Service),
        }
        .map_err(Into::into)
    }

    pub(crate) fn settle_positive_once(&mut self) -> Result<(), Error> {
        match &mut self.native {
            RootControllerPeerStorageV1::Initial(original) => original.settle_positive_once_v1(),
            RootControllerPeerStorageV1::Purpose(original) => original.settle_positive_once(),
            RootControllerPeerStorageV1::InitialTaken => return Err(Error::Service),
        }
        .map_err(Into::into)
    }

    pub(crate) fn require_completed(&self) -> Result<(), Error> {
        match &self.native {
            RootControllerPeerStorageV1::Initial(original) => original.require_completed_v1(),
            RootControllerPeerStorageV1::Purpose(original) => original.require_completed(),
            RootControllerPeerStorageV1::InitialTaken => return Err(Error::Service),
        }
        .map_err(Into::into)
    }

    pub(crate) fn property_failure_view_v1(
        &self,
    ) -> Option<aos_systemd_client::FixedPid1PropertyFailureViewV1<'_>> {
        match self.native_original_v1() {
            Ok(original) => original.property_failure_view_v1(),
            Err(_) => None,
        }
    }

    pub(crate) fn failure(&self) -> Option<&(dyn StdError + 'static)> {
        match &self.native {
            RootControllerPeerStorageV1::Initial(original) => original.failure_v1(),
            RootControllerPeerStorageV1::Purpose(original) => original.failure(),
            // The whole actual cause is retained by the native programme, not
            // replaced here by a later missing-slot diagnostic.
            RootControllerPeerStorageV1::InitialTaken => None,
        }
    }

    pub(crate) fn observe_prearmed_current_into_v1(
        &self,
        stream: &RetainedUnixStream,
        sample: &mut RootControllerPeerCurrentSampleV1,
    ) -> Result<(), Error> {
        self.native_original_v1()?
            .observe_prearmed_current_into_v1(stream, &mut sample.native)
            .map_err(Into::into)
    }

    pub(crate) fn native_original_v1(
        &self,
    ) -> Result<&native::RootSelectedControllerPeerOriginalV1<'startup>, Error> {
        match &self.native {
            RootControllerPeerStorageV1::Initial(original) => {
                original.native_peer_original_v1().map_err(Into::into)
            }
            RootControllerPeerStorageV1::Purpose(original) => Ok(original),
            RootControllerPeerStorageV1::InitialTaken => Err(Error::Service),
        }
    }

    pub(crate) fn from_startup_original_v1(
        original: aos_sandbox_policy::native::RootStartupControllerPeerOriginalV1<'startup>,
    ) -> Self {
        Self {
            native: RootControllerPeerStorageV1::Initial(original),
        }
    }

    pub(crate) fn startup_original_v1(
        &self,
    ) -> Result<&aos_sandbox_policy::native::RootStartupControllerPeerOriginalV1<'startup>, Error>
    {
        match &self.native {
            RootControllerPeerStorageV1::Initial(original) => Ok(original),
            RootControllerPeerStorageV1::Purpose(_) | RootControllerPeerStorageV1::InitialTaken => Err(Error::Service),
        }
    }

    pub(crate) fn startup_original_mut_v1(
        &mut self,
    ) -> Result<&mut aos_sandbox_policy::native::RootStartupControllerPeerOriginalV1<'startup>, Error>
    {
        match &mut self.native {
            RootControllerPeerStorageV1::Initial(original) => Ok(original),
            RootControllerPeerStorageV1::Purpose(_) | RootControllerPeerStorageV1::InitialTaken => Err(Error::Service),
        }
    }

    // Only the private accepted Flight calls these custody operations. They
    // preserve this same wrapper; no native peer is reconstructed from DATA.
    pub(in crate::normal_root) fn take_initial_original_v1(
        &mut self,
    ) -> Result<aos_sandbox_policy::native::RootStartupControllerPeerOriginalV1<'startup>, Error> {
        match std::mem::replace(&mut self.native, RootControllerPeerStorageV1::InitialTaken) {
            RootControllerPeerStorageV1::Initial(original) => Ok(original),
            original => {
                self.native = original;
                Err(Error::Service)
            }
        }
    }

    pub(in crate::normal_root) fn initial_custody_control_bytes_v1() -> Option<usize> {
        use std::mem::size_of;
        type Producer<'a> = aos_sandbox_policy::native::RootStartupControllerPeerOriginalV1<'a>;
        size_of::<(&mut Self, RootControllerPeerStorageV1<'startup>)>().checked_mul(3)?
            .checked_add(size_of::<RootControllerPeerStorageV1<'startup>>().checked_mul(3)?)?
            .checked_add(size_of::<Result<Producer<'startup>, Error>>().checked_mul(3)?)?
            .checked_add(size_of::<Option<usize>>().checked_mul(3)?)
    }

    pub(crate) fn initial_interface_control_bytes_v1() -> Option<usize> {
        use std::mem::size_of;
        size_of::<Self>().checked_mul(2)?
            .checked_add(size_of::<RootControllerPeerStorageV1<'_>>().checked_mul(2)?)?
            .checked_add(size_of::<aos_sandbox_policy::native::RootStartupControllerPeerOriginalV1<'_>>().checked_mul(3)?)?
            .checked_add(size_of::<Result<&native::RootSelectedControllerPeerOriginalV1<'_>, Error>>().checked_mul(3)?)?
            .checked_add(size_of::<Result<&aos_sandbox_policy::native::RootStartupControllerPeerOriginalV1<'_>, Error>>().checked_mul(3)?)?
            .checked_add(size_of::<Result<&mut aos_sandbox_policy::native::RootStartupControllerPeerOriginalV1<'_>, Error>>().checked_mul(3)?)?
            .checked_add(size_of::<aos_sandbox_policy::native::RootControllerPeerProvisionOriginalV1>().checked_mul(3)?)?
            .checked_add(size_of::<Option<aos_sandbox_policy::native::RootControllerPeerProvisionOriginalV1>>().checked_mul(3)?)?
            .checked_add(size_of::<Result<Self, Error>>().checked_mul(3)?)?
            .checked_add(size_of::<Result<(), Error>>().checked_mul(12)?)?
            .checked_add(size_of::<&Self>().checked_mul(9)?)?
            .checked_add(size_of::<&mut Self>().checked_mul(9)?)?
            .checked_add(size_of::<Option<usize>>().checked_mul(3)?)
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
    pub(in crate::normal_root) fn native_original_mut_v1(
        &mut self,
    ) -> &mut native::RootSelectedControllerCurrentSampleV1 {
        &mut self.native
    }

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
