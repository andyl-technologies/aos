//! Adapts the actual native selected owner to the private Root role wrapper.
//!
//! All image preparation and sealed native tuple ownership stay in one lower
//! owner. The role adds its own private startup wrapper and genuine R link;
//! public field DATA cannot construct either of those originals.

use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
use aos_sandbox_broker::receiving::{RootInitialReceivingOriginalV1, RootSelectedStartupOriginalV1};
use crate::controller_resource_reservation::ResourceReservationErrorV1;
use super::{NormalRootStartupErrorV1, ProductionNormalRootStartupV1};

#[derive(Default)]
pub(crate) struct RootSelectedStartupReceivingV1 {
    native: RootSelectedStartupOriginalV1,
    completed: Option<ProductionNormalRootStartupV1>,
}

impl RootSelectedStartupReceivingV1 {
    pub(crate) fn demand(initial: &RootInitialReceivingOriginalV1)
        -> Result<ResourceVector, ResourceReservationErrorV1>
    {
        let invalid = || ResourceReservationErrorV1::EnrollmentUnavailable;
        let native = RootSelectedStartupOriginalV1::demand(initial).map_err(|_| invalid())?;
        let bytes = std::mem::size_of::<Self>().checked_mul(2)
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<ProductionNormalRootStartupV1>().checked_mul(2)?))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<ResourceVector>().checked_mul(4)?))
            .ok_or_else(invalid)?;
        // Actual wrapper two fields and startup three fields in both carriers,
        // plus native/adapter/combined/returned financial carriers four.
        let adapter = ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(bytes).map_err(|_| invalid())?)
            .with(D::MetadataEntries, 2 * 2 + 3 * 2 + 4);
        native.checked_add(adapter).map_err(|_| invalid())
    }

    pub(crate) fn prepare_once(
        &mut self, identities: [u32; 4], initial: &mut RootInitialReceivingOriginalV1,
    ) -> Result<(), NormalRootStartupErrorV1> {
        self.native.prepare_once(identities, initial).map_err(Into::into)
    }

    pub(crate) fn assemble_once(&mut self, initial: &mut RootInitialReceivingOriginalV1)
        -> Result<(), NormalRootStartupErrorV1>
    {
        self.native.assemble_once(initial)?;
        if let Some(native) = self.native.take_completed() {
            self.completed = Some(ProductionNormalRootStartupV1 {
                native, receiving: None, receiving_financial: None,
            });
            Ok(())
        } else {
            Err(NormalRootStartupErrorV1::Profile)
        }
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.native.failure()
    }

    pub(crate) fn completed(&self) -> Option<&ProductionNormalRootStartupV1> {
        if self.failure().is_some() { return None; }
        self.completed.as_ref()
    }

    pub(crate) fn take_completed(&mut self) -> Option<ProductionNormalRootStartupV1> {
        self.completed()?;
        self.completed.take()
    }

    pub(crate) fn attach_serving_financial_once_v1(
        &mut self,
        initial: &mut RootInitialReceivingOriginalV1,
    ) -> Result<(), NormalRootStartupErrorV1> {
        self.completed().ok_or(NormalRootStartupErrorV1::Service)?;
        let startup = self.completed.as_mut().ok_or(NormalRootStartupErrorV1::Service)?;
        if startup.receiving.is_some() || startup.receiving_financial.is_some() {
            initial.latch_root_refusal_v1();
            return Err(NormalRootStartupErrorV1::Service);
        }
        let financial = initial.journal_financial_original_v1()
            .map_err(|_| NormalRootStartupErrorV1::Service)?;
        financial.require_startup_association_v1(&startup.native)
            .map_err(|_| NormalRootStartupErrorV1::Service)?;
        // The selected native graph is still owned here. No shared Journal
        // or published U exists until the caller takes this completed Startup.
        startup.receiving_financial = Some(financial);
        Ok(())
    }
}
